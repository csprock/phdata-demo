import java.util.HashMap;
import java.util.Map;

/* This class is equivalent to the Pane class in python */

public class Pane{

  private int timestamp;
  HashMap<String, Integer> ip_list = new HashMap<String, Integer>();
  private int n_requests = 0;

  public pane(int ts){
    timestamp = ts;
  }


  public void Update(String ip){

    if (ip_list.containsKey(ip)){
      int a = ip_list.get(ip);
      ip_list.put(ip, a + 1);
    } else{
      ip_list.put(ip, 1);
    }
    n_requests += 1;
  }


  public float computeMean(){

    int denom = ip_list.size();
    int numer = 0;

    for (int value: ip_list.values()){
      numer += value;
    }

    float denom1 = denom;
    float numer1 = numer;

    return numer1/denom1;
  }

  public double computeSD(){
    float sd_temp = 0;
    float mean = computeMean();

    for (int value: ip_list.values()){
      float temp = value - mean;
      sd_temp += Math.pow(temp, 2);
    }
    return Math.sqrt(sd_temp);
  }
}
