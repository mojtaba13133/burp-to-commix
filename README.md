Welcome to Burp-to-Commix

As you know, Command Injection is a security vulnerability with critical severity. If you are a hacker you know it as well that it takes a lot of times to find a command injection vulnerability on a target. It will be worse if you are a penetration tester. You must check this vulnerability on all of target URLs by intercepting packets using Burp Suit or other tools and in big Portals it’s not easy.

I have good news for hackers and pen testers. I made it easier by my new python script. The only thing you should do, is exporting your packets as a burp suit state file. The rest of steps will done by my script. I called me script “Burp-TO-Commix” and I will explain the test process from the beginning.

You can find the latest version of commix in the repository below
https://github.com/commixproject/commix

Usage

    Usage: ./burp2commix.py [options]

    Options: -f, --file

    Options: -o, --outputdirectory

    Options: -s, --commixpath

    Options: -c, --switch commix


    Example: python burp2commix.py -f [BURP-STATE-FILE] -o [OUTPUT-DIRECTORY] -s [SQLMap-Path] -c ["Commix-Switch"]

python burp2commix.py -s "./" -f "./in-file" -o "./out-file" -c " --proxy=http://127.0.0.1:8081 --cookie=  --batch"

How to Create Request/Response File in BurpSuite

    Select Your Request
![1](https://github.com/mojtaba13133/burp-to-commix/assets/44875173/5217e31f-2c5c-4604-87e8-7412dfcec132)

Create Request/Response File

    Right Clicke one one of these selected requests
![2](https://github.com/mojtaba13133/burp-to-commix/assets/44875173/e38914f1-917a-4b25-86c7-02d42cd82344)

Create Request/Response File

    Uncheck Base64 Option and create your requests/responses file
![3](https://github.com/mojtaba13133/burp-to-commix/assets/44875173/38a1da06-608a-4240-a881-daace251e9a9)

Create Request/Response File
