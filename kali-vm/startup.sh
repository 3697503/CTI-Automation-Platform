#!/bin/bash

msfrpcd -U msf -P metasploit -f 

# Add purple-ops modules
mdkir ~/.ms4/modules/post/windows/purple
unzip /vagrant/purple.zip -d ~/.ms4/modules/post/windows/purple/ 
