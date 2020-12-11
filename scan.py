# scan.py
# takes a pcap file and will return a list of hosts that have been in contact with your ip via http
# arguments(1): pcap filename

# import libraries
import sys
import dpkt
import socket
#support import for python 2.x & 3.x
try:
    import tkinter
    from tkinter import messagebox
except ImportError:
    import Tkinter
    import tkMessageBox as messagebox

# hide main tk window
root = tkinter.Tk()
root.withdraw()

notSecure = 0 #flag to determine if http data was found in the pcap file
addressList = [] #list of addresses communicated with via http
addresses = "" #string of address separated by commas
myIp = socket.gethostbyname(socket.gethostname()) #ip address of local computer on the network

# if ip address is 127.0.0.1, then no internet connection is available and program cannot function properly
if (myIp == "127.0.0.1"):
    tkinter.messagebox.showerror(title=None, message="Please connect to the internet to run this program")
    exit()

# if there is an error while running this program, the error will be caught and displayed as a message box
try:
    # open the file specified by the user via command line
    with open(sys.argv[1], "rb") as myFile:
        pcap = dpkt.pcap.Reader(myFile)
        for _, buffer in pcap:
            # get the ethernet frame from the buffer
            eth = dpkt.ethernet.Ethernet(buffer)
            # get the ip data
            ip = eth.data
            #get the tcp data
            tcp = ip.data
            # try to decode the source and destination ip, and if it's not possible then skip it
            try:
                srcAdr = socket.inet_ntoa(ip.src)
                dstAdr = socket.inet_ntoa(ip.dst)
            except:
                pass
            # check to see if the tcp is a valid dpkt.tcp.TCP object
            if isinstance(tcp, dpkt.tcp.TCP):
                # try to get the http request data, and if it's not possible then skip it
                try:
                    http = dpkt.http.Request(tcp.data)
                    # ensure that it is our ip that is communicationg with address
                    if (srcAdr == myIp or dstAdr == myIp):
                        #  get the host address from the http data
                        address = http['headers']['host']
                        # set notSecure flag to 1 to raise proper events later in the code
                        notSecure = 1
                        #make certain that the address is not already in the addressList and add to list
                        if not address in addressList:
                            addressList.append(address)
                except dpkt.dpkt.UnpackError:
                    pass
    # determine if any http connections were found
    if (notSecure):
        # loop through the addressList and create a comma-delimited string of addresses
        for address in addressList:
            if (addresses != ""):
                addresses = addresses + ', ' + address
            else:
                addresses = addresses + address
        # notify the user of addresses in which they have established connection via http
        tkinter.messagebox.showwarning(title="You have had insecure http connections with the following addresses:", message=addresses)
    else:
        # notify the user that no connections were found via http
        tkinter.messagebox.showinfo(title="Congratulations!", message="No insecure http connections found")
except Exception as e:
    tkinter.messagebox.showerror(title=None, message=str(e))

