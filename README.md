## Instructions to run Q1

1. Use 6.pcap file
2. Open 2 sessions of terminal
3. In first session type g++ Server.cpp -o Server, press enter and then type ./Server then press enter. This starts the server which will be indicated by a message saying Listening on UDP port- 5555.
3. In second session type g++ Parse.cpp -o Parse -lpcap, press enter and then type ./Parse and press enter. This will start the run the client which will then send and recieve packets to and from the server. The table of resolutions will be stored in client_resolutions.csv

## File information

Server.cpp contains server code

Parse.cpp contains Client code

client_resolutions.csv contains table
