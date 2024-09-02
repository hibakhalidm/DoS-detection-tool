
# Cyber Security - Dos Detection Tool (CMP3750M_Assessment_02)


## Overview
A denial of service (DoS) attack involves flooding a targeted device with a considerable amount of resources in the hopes of bringing a service to a halt and stop legitimate users from being able to access a service (CISA, 2009). The ‘DoS Identification Tool’ was created in Python and is used to identify these concerning amounts of resources being sent to the device it is being ran on. It was created and recommended to be used in Kali Linux for optimal results. 


## Installation and Usage Guide
To install the tool, the .zip file should be downloaded and extracted to a chosen location. From there, ensure pip is installed and run the command: ‘python -m pip install -r requirements.txt’. This will install the appropriate libraries required for the tool to operate. Once the ‘main.py’ file is running, a ‘tkinter’ GUI is presented, and the tool is ready for use.

The DoS attack results window will report a message that there is current data as the tool has not been used before, so to start gathering data, the ‘Start DoS Detection’ button should be clicked, which will start the tool and detect any incoming packets. While the tool is running and no DoS attack is happening, there may be random packets being received from various IP addresses, which is normal. The count number from these addresses should remain relatively low. The tool can be ran in the background on any device that is susceptible to a DoS attack and has very low-performance requirements to ensure an attack is not missed.

Once the tool has been ran and successfully stopped at least once, the attack results window can be refreshed, and an output will be presented to the user. This contains the date and time the detection was started and reports that there was either no attack during that time or an attack detected and the IP address where it potentially came from. However, some attackers may use forged IP addresses propagated from 'behind' an Internet Service Provider's (ISP) aggregation point (Bass, 2001), suggesting that the IP address shown in an attack may not always be correct. An output of all compilations can be seen in the ‘dos-output.txt’ file, which can be taken and used for further analysis.


### References
Abhishta, A., van Rijswijk-Deij, R. and Nieuwenhuis, L.J.M. (2018). Measuring the Impact of a Successful DDoS Attack on the Customer Behaviour of Managed DNS Service Providers. Proceedings of the 2018 Workshop on Traffic Measurements for Cybersecurity. [Accessed 19 Mar. 2021].

Bass, S. (2001). SANS Institute: Reading Room - Threats/Vulnerabilities. [online] www.sans.org. Available at: https://www.sans.org/reading-room/whitepapers/threats/paper/469 [Accessed 18 Mar. 2021].
