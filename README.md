# ILLUMIO CODING CHALLENGE

## This was a coding challenge by Illumio, as a part of their interviewing process.

The Python script takes rules for a Firewall from the fw.csv file, and adds them to a Python Dictionary
Later, we can check if a particular combination of direction (outbound/inbound), protocol (tcp/udp), port numbers [1-65535] and IP addresses [0.0.0.0 to 255.255.255.255] should be allowed by the firewall or not.

### Design
The firewall rules are stored in a dictionary within a dictionary. I decided to split the direction of the packet as 2 separate keys. 
Within each key, I had another dictionary where I separated the protocols. 
Although this takes up space to store, this would help with time because the program would not have to search through the entire list of rules, just the ones with the input direction and protocol.
I decided to use direction and protocol as my keys is because they were single strings as opposed to ports and IPs which had both single values and ranges.

### Improvements
    1. Since there can be multiple ip addresses for a port, searching through the IPs will take O(n) time, since we have stored the IPs in a list
    [see: https://wiki.python.org/moin/TimeComplexity]. 
    2. This time can be reduced by writing a custom searching function (Eg. binary search or hashing)
    3. If binary search needs to be implemented, the IPs need to be in their decimal form (or at least be converted to decimal from before searching), and also should be in sorted order
    4. If hashing needs to be implemented, minor changes to the structure of the dictionary has to be made. In place of a List (which is currently a value at 
    {inbound:tcp{
                    port_number: List[]
                },
            udp{
                    port_number: List[]
                },
        outbound {...}})
    another dictionary can be used, with the key as IP address and value as any dummy value (Eg. 1). Thus, searching can take place in O(1) time.
    5. However, this will increase the space used by the dictionary. O(2nm) ~ O(nm) n keys, with m sub keys and each key having a value. This dummy value takes up extra space (represented by the factor '2'),
       which is not present in case of a List
    
    6. In case of our original dictionary, space used is of the order O(nm) [n keys with values as arrays of size m]
    7. So there is a tradeoff between time required to search and space needed to store the rules. In this case, I have chosen Space over Performance, since there weren't many rules to add to my dictionary. So searching won't take much time
    8. Another improvement can be, implementing command line arguments, wherein, direction, protocol, port and ip address can be given to the code as command line arguments, instead of hardcoding them in the program
    
### Testing
1. I considered a couple of combinations of directions, protocols, port numbers and IP addresses, some of them included in the rules and 
some of them not, and tested their output.
2. Since it was mentioned that the input parameters will be valid and according to the specifications, i did not test for invalid input.
3. I could not implement Unit or Integration testing since I do not have experience in testing applications.

### Comments
I thank Illumio for giving this challenge as opposed to a Hackerrank coding test. I definitely got to learn a lot more doing this challenge, that i would ever learn with a coding test.
It was really fun to do this project, and I hope to hear a positive response from the team! Also, I would love to discuss any shortcomings or improvements needed in this project!

##Teams:
I would love to work with the Data Team as i have a knack for Data Analysis and Visualisation. I also have some experience in Machine Learning and have built a couple of projects to strengthen my skills in the same.
I have enrolled myself in Statistics and Big Data Courses at my University, which will be useful to me for my Internship.

I have contacted the Policy and Platform teams to know more about the key requirements that the teams look for in a candidate, and also how can I bridge the gap between my skills and the requrements.
