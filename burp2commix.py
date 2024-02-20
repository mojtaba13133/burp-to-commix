try:
    import sys
    import os
    from bs4 import BeautifulSoup
    import os.path
    import argparse
    import codecs

except Exception as e:
    print(e)
    exit()


def banner():
    print(r"""
    #######################################################################

__________                      ___________      _________                        .__        
\______   \__ _______________   \__    ___/___   \_   ___ \  ____   _____   _____ |__|__  ___
 |    |  _/  |  \_  __ \____ \    |    | /  _ \  /    \  \/ /  _ \ /     \ /     \|  \  \/  /
 |    |   \  |  /|  | \/  |_> >   |    |(  <_> ) \     \___(  <_> )  Y Y  \  Y Y  \  |>    < 
 |______  /____/ |__|  |   __/    |____| \____/   \______  /\____/|__|_|  /__|_|  /__/__/\_ \
        \/             |__|                              \/             \/      \/         \/    
                                                                
                                                                   
    #    Created By: Seyed Mojtaba    E-Mail: mrtzs.1997@gmail.com    #
    #######################################################################""")

def usage():
    print(" ")
    print("  Usage: ./burp-to-commix.py [options]")
    print("  Options: -f, --file               <BurpSuit State File>")
    print("  Options: -o, --outputdirectory    <Output Directory>")
    print("  Options: -s, --Commixpath         <Commix Path>")
    print("  Options: -c, --config             <Commix options>")
    print("  Example: python burp-to-commix.py -f [BURP-STATE-FILE] -o [OUTPUT-DIRECTORY] -s [Commix-Path] -c [\"Commix Options\"]")
    print(" ")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file")
    parser.add_argument("-o", "--outputdirectory")
    parser.add_argument("-s", "--Commixpath")
    parser.add_argument("-c", "--config")
    args = parser.parse_args()

    if not args.file or not args.outputdirectory or not args.Commixpath:
        banner()
        usage()
        sys.exit(0)
    
    if args.config:
        configvalue = args.config
    else:
        configvalue = ""

    vulnerablefiles = []
    banner()
    filename = args.file
    directory = args.outputdirectory
    Commixpath = args.Commixpath
    if not os.path.exists(directory):
        os.makedirs(directory)

    if sys.platform.startswith("win32"):
        runWindows(filename, directory, Commixpath, configvalue, vulnerablefiles)
    elif sys.platform.startswith("linux"):
        runLinux(filename, directory, Commixpath, configvalue, vulnerablefiles)
    else:
        print("[+] Error: Unsupported OS Detected!")

def runWindows(filename, directory, Commixpath, configvalue, vulnerablefiles):
    packetnumber = 0
    print(" [+] Exporting Packets ...")
    with open(filename, 'r') as f:
        soup = BeautifulSoup(f.read(), "html.parser")
        for i in soup.find_all("request"):
            packetnumber = packetnumber + 1
            print("   [-] Packet " + str(packetnumber) + " Exported.")
            # Remove cookie header
            request_text = i.text.strip()
            request_text_lines = request_text.split("\n")
            request_text_without_cookie = "\n".join([line for line in request_text_lines if not line.startswith("Cookie:")])
            outfile = open(os.path.join(directory, str(packetnumber) + ".txt"), "w")
            outfile.write(request_text_without_cookie)
        print(" ")
        print(str(packetnumber) + " Packets Exported Successfully.")
        print(" ")

    print(" [+] Testing Command Injection on packets ...  (Based on your network connection Test can take up to 5 minutes.)")
    for file in os.listdir(directory):
        print("   [-] Performing Command Injection on packet number " + file[:-4] + ". Please Wait ...")
        os.system("python " + Commixpath + "\\commix.py -r " + os.path.dirname(os.path.realpath(
            __file__)) + "\\" + directory + "\\" + file + configvalue + " > " + os.path.dirname(
            os.path.realpath(__file__)) + "\\" + directory + "\\testresult" + file)
        if 'is vulnerable' in open(directory + "\\testresult" + file).read() or "Payload:" in open(
                directory + "\\testresult" + file).read():
            print("    - URL is Vulnerable.")
            vulnerablefiles.append(file)
        else:
            print("    - URL is not Vulnerable.")
        print("    - Output saved in " + directory + "\\testresult" + file)
    print(" ")
    print("--------------")
    print("Test Done.")
    print("Result:")
    if not vulnerablefiles:
        print("No vulnerabilities found on your target.")
    else:
        for items in vulnerablefiles:
            print("Packet " + items[:-4] + " is vulnerable to Command Injection. for more information please see " + items)
    print("--------------")
    print(" ")

def runLinux(filename, directory, Commixpath, configvalue, vulnerablefiles):
    packetnumber = 0
    print(" [+] Exporting Packets ...")
    with open(filename, 'r') as f:
        soup = BeautifulSoup(f.read(), "html.parser")
        for i in soup.find_all("request"):
            packetnumber = packetnumber + 1
            print("   [-] Packet " + str(packetnumber) + " Exported.")
            # Remove cookie header
            request_text = i.text.strip()
            request_text_lines = request_text.split("\n")
            request_text_without_cookie = "\n".join([line for line in request_text_lines if not line.startswith("Cookie:")])
            outfile = open(os.path.join(directory, str(packetnumber) + ".txt"), "w")
            outfile.write(request_text_without_cookie)
        print(" ")
        print(str(packetnumber) + " Packets Exported Successfully.")
        print(" ")

    print(" [+] Testing Command Injection on packets ...  (Based on your network connection Test can take up to 5 minutes.)")
    for file in os.listdir(directory):
        #The following few lines solves an issue with the character encoding.
        #Burp in Kali exports the HTTP history as UTF-16LE which was resulting
        #in the individual request files not being read successfully by Commix
        #There is probably a cleaner way to do this.
        cmd = "iconv -f utf-16le -t ascii %s > %s_ascii" % (os.path.dirname(os.path.realpath(__file__)) + "/" + directory + "/" + file,os.path.dirname(os.path.realpath(__file__)) + "/" + directory + "/" + file)
        os.system(cmd)
        cmd = "cat %s_ascii > %s" % (os.path.dirname(os.path.realpath(__file__)) + "/" + directory + "/" + file,os.path.dirname(os.path.realpath(__file__)) + "/" + directory + "/" + file)
        os.system(cmd)
        cmd = "rm %s_ascii" % (os.path.dirname(os.path.realpath(__file__)) + "/" + directory + "/" + file)
        os.system(cmd)
        print("   [-] Performing Command Injection on packet number " + file[:-4] + ". Please Wait ...")
        cmd = "python " + Commixpath + "/commix.py -r " + os.path.dirname(os.path.realpath(__file__)) + "/" + directory + "/" + file + configvalue + " > " + os.path.dirname(os.path.realpath(__file__)) + "/" + directory + "/testresult" + "_" + file
        os.system(cmd)
        if 'is vulnerable' in open(directory + "/testresult" + "_" + file).read() or "Payload:" in open(
                directory + "/testresult" + "_" + file).read():
            print("    - URL is Vulnerable.")
            vulnerablefiles.append(file)
        else:
            print("    - URL is not Vulnerable.")
        print("    - Output saved in " + directory + "/testresult" + file)
        print(" ")
        print("--------------")
        print("Test Done.")
        print("Result:")
        if not vulnerablefiles:
            print("No vulnerabilities found on your target.")
        else:
            for items in vulnerablefiles:
                 print("Packet " + items[:-4] + " is vulnerable to Command Injection. for more information please see " + items)
        print("--------------")
        print(" ")


if __name__ == "__main__":
    main()