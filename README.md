# ARP Poisoning
Scripts to simulate both an ARP poisoning attack and defense (on Local area network).

Install dependencies by running `pip install -r requirements.txt` in your console before running the below scripts.

To test this project, first run the Defense script and set it to sniff for a high amount of seconds, then run the attack script and see how it is detected in the defense console.

## Contents
* [Disclaimer](#disclaimer)
* [Attack](#attack)
* [Defense](#defense)

## Attack
Script that sends fake arp packets to victims in order to change their ip-arp relations to the attacker's machine (arp).

Run the script in your console by writing `python3 attack.py`
Then input the required parameters

## Defense
Script to sniff the network, collect arp states, and inform the user in case a suspected arp spoofing attack was detected.

Run the script in your console by writing `python3 defense.py`
Then input the required parameters


### Collaborators:
- Edmond Samaha
- Aline Challita
- Hussein Hammoud
- Hiba Houhou 

# Disclaimer
All information and code available in this repository are for educational purposes only. Use them at your own discretion. The authors of this repository cannot be held responsible for any damages caused or illegal usage of the information given.
