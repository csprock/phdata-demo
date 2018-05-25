import math

class Pane:
    '''
    This class represents a time period. Its contains a dictionary of IP addresses
    and acumulators for the number of requests each one makes. As the program reads logs,
    the IP addresses encountered in a time period are stored in this object. Each time a new
    IP is encountered it is added to the list. If a previously encoutered IP is read, its request
    counter is incremented.

    It also contains a method for computing the mean and standard deviation of the number
    of requests per IP stored in the Pane.
    '''


    def __init__(self, timestamp):

        self.timestamp = timestamp
        self.ip_list = dict()
        self.n_requests = 0

    def update(self, ip):
        '''
        Update the IP address list with incoming IP. If not in list,
        will be added. If is in list, its counter is incremented.
        The total number of requests is incremented.
        '''

        if ip not in self.ip_list:
            self.ip_list[ip] = 1
        else:
            self.ip_list[ip] += 1

        self.n_requests += 1

    def ip_stats(self):
        '''
        Compute the mean and standard deviation of the number of requests
        per IP address in this Pane.
        '''

        numer, denom, sd_temp = 0, 0, 0

        # Compute mean.
        for k, v in self.ip_list.items():
            numer += v
            denom += 1
        mean = numer / denom

        # Compute standard deviation.
        for k, v in self.ip_list.items(): sd_temp += (mean - v)**2
        sd = math.sqrt(sd_temp)

        return mean, sd



class Window:

    '''
    This class stores sequence of Panes representing a time window. This class
    contains methods for shifting the Window with the addition of a new Pane.
    It also contains a method for computing the mean and standard deviation of
    the number of requests in each Pane.
    '''


    def __init__(self, window_length):

        self.window_length = window_length
        self.panes = []
        self.ave_requests = 0
        self.sd_requests = 0

    def __len__(self):
        return len(self.panes)

    def __contains__(self, timestamp):
        for p in self.panes:
            if p.timestamp == timestamp:
                return True

        return False

    def shift_window(self, new_pane):
        '''
        Shifts window by adding new Pane to the end of current window and dropping
        the oldest Pane if the length of the current window is equal to the maximum
        window length. Otherwise, the new Pane is simply added.
        '''
        assert isinstance(new_pane, Pane)

        if self.__len__() < self.window_length:
            self.panes.append(new_pane)
        else:
            try:
                self.panes.pop(0)
            except IndexError:
                pass
            finally:
                self.panes.append(new_pane)

    def get_request_stats(self):
        '''
        Computes and returns mean and standard deviation of the number of
        requests per Pane (timestamp) in the Window.
        '''

        numer, sd_temp = 0, 0

        # Compute mean
        for p in self.panes: numer += p.n_requests
        self.ave_requests = numer / self.__len__()

        # Compute standard deviation
        for p in self.panes: sd_temp += (self.ave_requests - p.n_requests)**2
        self.sd_requests = math.sqrt(sd_temp)

        return self.ave_requests, self.sd_requests



class AttackDetector:

    '''
    AttackDetector class holds a Window of previous time periods and handles the logic
    for processing incoming data and updating the Panes and the Windows and detecting a
    surge in traffic.

    The class works by keeping a Window of Panes representing a user-defined number of
    previous time periods before the current one. A Pane representing the current time
    period is kept separately and info about incoming log records are stored in this Pane.
    When a new time period is encountered, the Window is updated with the Pane. The a new Pane
    is created for the current timestamp.

    Once the new timestamp is encountered, the attack detection method is run on the current
    timestamp that is about to be added to the Window. This assumes data are in chronological
    order.
    '''

    def __init__(self, window_length, log_path):

        self.window = Window(window_length)

        self.current_pane = None
        self.current_timestamp = None

        self.log_path = log_path

        # attack status
        self.status = False

        self.normal_request_stats = None
        self.normal_ip_stats = None


    def process_data(self, ip, timestamp):
        '''
        Processes a log record. Takes the IP address and the timestamp.
        '''
        # Create current pane if does not exist already. This logic will only be run the first time data
        # is processed.
        if self.current_pane is None:
            self.current_timestamp, self.current_pane = timestamp, Pane(timestamp)

        if timestamp != self.current_timestamp:
            # Once a new timestamp is encountered, scan for attack on the previous
            # timestamp and then add it to the window, updating the current timestamp
            # to be the newly encountered timestamp.

            if timestamp not in self.window:

                # must have at least two panes in window before attack scanning
                if len(self.window) > 1: self.scan_for_attack()                        # scan for attack

                print("Timestamp: %s, Number of requests: %s, Attack: %s" % (self.current_timestamp, self.current_pane.n_requests, self.status))

                self.window.shift_window(self.current_pane)                            # shift window
                self.current_timestamp, self.current_pane = timestamp, Pane(timestamp) # update current timestamp and add new pane

        else:
            self.current_pane.update(ip)  # update current Pane with new IP request information




    def check_ip_stats(self):
        '''
        Check the number of requests each IP address in the current Pane is making and
        compare these to average of the last normal period of activity. If IP address is found that is
        making > 2 SD requests above normal then return True, otherwise return False.
        '''

        # indicator for if number of requests in current Pane is > 2 SD's away
        # from the mean of the Window average.
        #ip_status = False


        if self.status:
            # If currently under attack, compare IP statistics to normal_ip_stats.
            for ip, v in self.current_pane.ip_list.items():
                if v > self.normal_ip_stats[0] + 2*self.normal_ip_stats[1]:
                    return True

        else:
            # If not currently under attack, set normal_ip_stats to IP statistics of the previous Pane.
            # The compare the number of requests for the IPs in the current Pane to these.
            self.normal_ip_stats = self.window.panes[-1].ip_stats()

            for ip, v in self.current_pane.ip_list.items():
                if v > self.normal_ip_stats[0] + 2*self.normal_ip_stats[1]:
                    return True

        return False


    def write_ips_to_logs(self):
        ''' Write IP addresses that number of requests > 2 SD's above normal levels to file.'''

        for ip, v in self.current_pane.ip_list.items():
            if v > self.normal_ip_stats[0] + 2*self.normal_ip_stats[1]:
                with open(self.log_path, 'a+') as log:
                    log.write('{}\n'.format(ip))



    def scan_for_attack(self):
        '''
        Checks if the number of requests in the current Pane is greater than 2 SD's above the mean
        of the number of requests in the Window. Also check the number of requests per IP address
        in the current Pane and if is > 2 SD above the average of the previous Pane. If both conditions
        are true, market as attack and write suspected IPs to log.
        '''

        if self.status:
            # If already under attack, compare to number of requests to normal levels.
            if self.current_pane.n_requests > self.normal_stats[0] + 2*self.normal_stats[1] and self.check_ip_stats():
                self.write_ips_to_logs()
            else:
                self.status = False
        else:
            # If not under attack, compare to number of requests in the Window.
            # If if attack detected, update status and save the Window statistics for
            # future comparison in normal_stats

            # Get the average and SD of the number of requests over the Window.
            ave, sd = self.window.get_request_stats()

            if self.current_pane.n_requests > ave + 2*sd and self.check_ip_stats():
                self.status = True
                self.normal_stats = (ave, sd)
                self.write_ips_to_logs()
