#!/usr/bin/env python

# Domain Name Scanner - A tool to scan provided domains and return their status.
#
# Description:
#   Scans domains and outputs status. Useful for outbound
#   web scanning, and ADCS ESC8 hunting without the need for
#   an authenticated or domain user account.
#
# Author:
#   Jessa (@manicPxiSIEMGirl)
#
#	Version 2.0
#	Updated: 3/14/26
#
###########################################################

###########################################################
#
# To Do:
#  1) Test EXC8 search in environment with ADCS and ESC 8
#
###########################################################

import codecs
import sys
import argparse
import os.path
import urllib.request
import requests

class scan:
	def __init__(self, inputFile, outputLocation, ADCS):
		self.__inputFile = inputFile
		self.__outputLocation = outputLocation
		self.__ADCS = ADCS

	def scan(self):
		try:
			f = open(self.__inputFile, "r")
			f.close()
		except:
			print("Input file not found. Please ensure the file is a valid .txt file stored in ",self.__inputFile)
			sys.exit(1)
			
		try:
			#scan
			print("Scanning")
			f = open(self.__inputFile, "r")
			if self.__ADCS:
				print("ADCS ESC8 Check")
				#ADCS ESC8 check
				for line in f.readlines():
					print(".")
					o = open(self.__outputLocation,"a")
					validURLSTR = "\"http://"+str(line).strip()+"/certsrv/certfnsh.asp\""
					garbageURLSTR = "\"http://"+str(line).strip()+"/invalid1234/garbage5678.asp\""
					print(validURLSTR)
					print(garbageURLSTR)
					try:
						#validCheck = urllib.request.urlopen(validURLSTR,timeout=500).getcode()
						validCheck = requests.head(validURLSTR,timeout=500).status_code
					except:
						validCheck = "Could not connect"
					try:
						#garbageCheck = urllib.request.urlopen(garbageURLSTR,timeout=500).getcode()
						arbageCheck = requests.head(garbageURLSTR,timeout=500).status_code
					except:
						garbageCheck = "Could not connect"
					print(validCheck)
					print(garbageCheck)
					if validCheck == 200 or validCheck == 401:
						if garbageCheck != 200 and garbageCheck != 401:
							o.write(str(line.strip())+"\n")
					o.close()
			else:
				#Scan for error codes
				for line in f.readlines():
					#scan line
					print(".")
					o = open(self.__outputLocation,"a")
					validHTTPURLSTR = "\"http://"+str(line).strip()+"\""
					validHTTPSURLSTR = "\"https://"+str(line).strip()+"\""
					print(validHTTPURLSTR)
					print(validHTTPSURLSTR)
					try:
						print("starting url checks")
						#checkHTTP = urllib.request.urlopen(validHTTPURLSTR,timeoutError=500).getcode()
						checkHTTP = requests.head(validHTTPURLSTR,timeout=500).status_code
					except:
						checkHTTP = "Could not connect"
					try:
						#checkHTTPS = urllib.request.urlopen(validHTTPSURLSTR,timeoutError=500).getcode()
						checkHTTPS = requests.head(validHTTPSURLSTR,timeout=500).status_code
					except:
						checkHTTP = "Could not connect"
					if checkHTTP == 200 or checkHTTPS == 200:
						check = 200
					else:
						check = "Could not Connect"
					writeSTR = line.strip()+","+str(checkHTTP).strip()+","+str(checkHTTPS).strip()+","+check+"\n"
					o.write(writeSTR)
					o.close()
			f.close()
		except:
			print("Scanning failed")

# Process command-line arguments.
if __name__ == '__main__':
	# Explicitly changing the stdout encoding format
	if sys.stdout.encoding is None:
		# Output is redirected to a file
		sys.stdout = codecs.getwriter('utf8')(sys.stdout)
	argParser = argparse.ArgumentParser(add_help = True, description = "Scans web pages and returns their status")
	argParser.add_argument('-inputFile', action='store', help='input of FQDN DNS host names to test the connection')
	argParser.add_argument('-outputFile', action='store', help='output file')
	argParser.add_argument('-outputDirectory', action='store' , help='output directory')
	argParser.add_argument('-ADCS', action=argparse.BooleanOptionalAction, help='Check input for ADCS ESC 8')

	#Error check empty expected items
	if len(sys.argv)==1:
		argParser.print_help()
		sys.exit(1)
	options = argParser.parse_args()
	if options.inputFile is None:
		print("An input file of line separated FQDN DNS names must be specified. This file should be a .txt file.")
		sys.exit(1)
	if options.outputFile is None:
		print("Please specify an output file name with -outputFile")
		sys.exit(1)
	if options.outputDirectory is None:
		options.outputDirectory = "./"

	#Append and handle file extensions and directory traversal
	try:
		if not(os.path.isdir(options.outputDirectory)):
			print("Please provide a valid directory path, or check permissions on the folder. The provided directory was: ",options.outputDirectory)
			sys.exit(1)
	except:
		sys.exit(1)
	if not(str(options.outputDirectory).endswith("/")):
		options.outputDirectory = options.outputDirectory + "/"
	if not(str(options.outputFile).endswith(".txt")) and options.ADCS:
		options.outputFile = options.outputFile + ".txt"
	if not(str(options.outputFile).endswith(".csv")) and not(options.ADCS):
		options.outputFile = options.outputFile + ".csv"

	#Create outputLocation
	outputLocation = ''
	if str(options.outputDirectory).endswith("/"):
		if str(options.outputFile).endswith(".txt") or str(options.outputFile).endswith(".csv"):
			outputLocation = str(str(outputLocation) + str(options.outputFile))
		else:
			print("Error with output file")
			sys.exit(1)
	else:
		print("Error with output directory")
		sys.exit(1)

    #Scan
	scanner = scan(options.inputFile,outputLocation,options.ADCS)
	try:
		scanner.scan()
	except:
		print("Scanning failed. This is due to a series of deeper failures. Maybe brush some salt into it?")
		sys.exit(1)