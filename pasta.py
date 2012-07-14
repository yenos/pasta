#!/usr/bin/env 

# == Pasta: PAssword STAtistics tool
#
# == Usage
# usage: pasta.py [-h] -f FILENAME -m MODE [-ms MODESEPARATOR] [-s SOURCE]
#                [-t TOP]
# optional arguments:
#   -h, --help            show this help message and exit
#   -f FILENAME, --filename FILENAME
#                         File's name where are stored passwords
#   -m MODE, --mode MODE  Define if your file contains only password (-m 0) or
#                         user and password (-m 1). If you choose mode 1, you
#                         have to define the user-password separator option -ms
#   -ms MODESEPARATOR, --modeseparator MODESEPARATOR
#                         [-m 1] Define the separator between the username and
#                         the password
#   -s SOURCE, --source SOURCE
#                         Name of the website from where are extract the
#                         passwords
#   -t TOP, --top TOP     Define the number of password include in the top list
#                         (default: 10)
#
#
# FILENAME: The file to analyse
# MODE: [0] for a password file
#	[1] for a user[separator]password file (require to set the -ms argument)
#
# == Example
# pasta -f password.txt -m 0 - t 20 -s google => analyse the password file from a google's dump and print the top20 of most used password
# > cat pu.txt
# cat up.txt 
# 	user:pass
# 	dezvc:123456
# 	johny:jphny
# 	azerty:azerty
# pasta -f up.txt -m 1 -ms :  => analyse the username:password combo file, and print the top10 of most used password
#
# == About
# Author:: Ronan Mouchoux (@yenos, <rmouchoux a gmail dot com>)
# Copyright:: Copyright (c) Ronan Mouchoux 2012
# Licence:: Creative Commons Attribution-Share Alike 2.0
#

import sys
import jellyfish
import argparse
from operator import itemgetter


EXIT_ON_MODE		=	100
EXIT_ON_SEPARATOR	=	101



class pasta:

	passList	=	{}
	userPassList	=	{}
	count 		=	0 

	#25 Worst Passwords of the Year 2011
	worstPass	=	   ["password",
				    "123456",
				    "12345678",
				    "qwerty",
				    "abc123",
				    "monkey",
				    "1234567",
				    "letmein",
				    "trustno1",
				    "dragon",
				    "baseball",
				    "111111",
				    "iloveyou",
				    "master",
				    "sunshine",
				    "ashley",
				    "bailey",
				    "passw0rd",
				    "shadow",
				    "123123",
				    "654321",
				    "superman",
				    "qazwsx",
				    "michael",
				    "football"]


#---------------------------------------------#	
#		   TOOLS		      #
#---------------------------------------------#		
	##=======================#
	#Load the password file  #
	#========================#
	def load(self, fn, mode, separator):
		f = open(fn,'r')
		for line in f:
			line = line.replace('\n','')
			if mode == 0:
				try:
					self.passList[line] 		+= 	1
				except KeyError:
					self.passList[line] 		= 	1 
			if mode == 1:
				combo = line.split(separator)
				self.userPassList[self.count]	=	combo
				try:
					self.passList[combo[1]] 	+= 	1
				except KeyError:
					self.passList[combo[1]] 	= 	1 
			self.count += 1
		
		f.close()

	##=======================#
	#Get the options	 #
	#========================#	
	def getargs(self):
		parser = argparse.ArgumentParser(description='Pasta (Password Statistics) is a tool design to produce statistics from a list of clear text password, or a list of user[separator]password.')
		parser.add_argument('-f','--filename', 		help="File's name where are stored passwords",required=True)
		parser.add_argument('-m','--mode', 		help="Define if your file contains only password (-m 0) or user and password (-m 1). If you choose mode 1, you have to define the user-password separator option -ms",required=True)
		parser.add_argument('-ms','--modeseparator', 	help="[-m 1] Define the separator between the username and the password", required=False)
		parser.add_argument('-s','--source', 		help="Name of the website from where are extract the passwords", required=False)
		parser.add_argument('-t','--top', 		help="Define the number of password include in the top list (default: 10)", required=False)
		args = vars(parser.parse_args())

		
		separator 	= ""
		source 		= ""
		top		= 10
		
		fn = args['filename']

		mode = int(args['mode'])
		if mode != 0 and mode != 1:
			return EXIT_ON_MODE

		tmp = args['modeseparator']
		if tmp != None and mode == 1:
			separator = tmp
		elif tmp == None and mode == 1:
			return EXIT_ON_SEPARATOR
		

		tmp = args['source']
		if tmp != None:
			source = tmp

		tmp = args['top']
		if tmp != None:
			top=tmp
		return[fn, mode, separator, source, top]

#---------------------------------------------#	
#		   STAT			      #
#---------------------------------------------#	
	def stat(self, mode, source, top):
	
		#Preparation	
		lenghtM 	= 0
		passM 		= ""
		lenghtm 	= 7
		passm 		= ""
		uniq 		= 0
		lenghtTab 	= {}
		speCharTab	= {}
		for key in self.passList.keys():
			l 		=  len(key)
			if l > 0:
				try:
					lenghtTab[l] 	+= 1
				except KeyError:
					lenghtTab[l]	= 1
				if self.passList[key] == 1:
					uniq += 1
				if l > lenghtM:
					passM 	= key
					lenghtM = l
				elif l < lenghtm:
					passm 	= key
					lenghtm = l
		onlyNum 	= 0
		onlyUpper	= 0
		onlyLowAlpha 	= 0
		onlyAlpha	= 0
		alphaNum 	= 0
		speChar		= 0
		sourceC		= 0
		wp		= 0
		wpProx		= 0
		uEqP		= 0
		uEqPProx	= 0
		for key in self.passList.keys():
		#Basics Stats
			l = len(key)
			if sum(key.lower().count(c) for c in 'azertyuiopqsdfghjklmwxcvbn') == l:
				onlyAlpha += 1
			if sum(key.count(c) for c in '0123456789') == l:
				onlyNum += 1
			elif sum(key.count(c) for c in 'azertyuiopqsdfghjklmwxcvbn') == l:
				onlyLowAlpha += 1
			elif sum(key.count(c) for c in 'AZERTYUIOPQSDFGHJKLMWXCVBN') == l:
				onlyUpper += 1
			elif sum(key.count(c) for c in '0123456789azertyuiopqsdfghjklmwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN') == l:
				alphaNum += 1
			elif sum(key.count(c) for c in '0123456789azertyuiopqsdfghjklmwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN') == 0:
				speChar += 1
			else:
				n 	= sum(key.count(c) for c in '0123456789azertyuiopqsdfghjklmwxcvbnAZERTYUIOPQSDFGHJKLMWXCVBN')
				s = l - n
				try:
					speCharTab[s] += 1
				except KeyError : 
					speCharTab[s] = 1
			
			if source in key:
				sourceC += 1
			if key in self.worstPass:
				wp += 1


		#Advanced Stat
			prox = False
			for p in self.worstPass:
				if 100*(jellyfish.damerau_levenshtein_distance(key, p))/(l+len(p)) < 20:
					prox = True
			if prox:
				wpProx += 1
		prox = False
		if mode == 1:
			for i in self.userPassList.keys():
				u	= self.userPassList[i][0]
				p	= self.userPassList[i][1]
				if u == p:
					uEqP 		+= 1
				if 100*(jellyfish.damerau_levenshtein_distance(u, p))/(len(u)+len(p)) < 20:
					uEqPProx 	+=1
		

		#Top Stat
		wpp 	= 0
		lpp	= 0
		sp	= 0
		topP	= {}
		topL	= {}
		topS	= {}
		for key, value in sorted(self.passList.items(), key=itemgetter(1), reverse=True)[:int(top)]:
			a 	=  100.00*value/(self.count)
			wpp 	+= a	 
			topP[key] = [value,a]
		for key, value in lenghtTab.items():
			if value > 0:
				a 	=  100.00*value/(self.count)
				if int(key) > 7:
					lpp 	+= a
				topL[key] = [value,a]
		for key, value in speCharTab.items():
			if value > 0:
				a 	=  100.00*value/(self.count)
				if int(key) > 2:
					sp	+= a
				topS[key] = [value,a]

		#Print Result
		print("# ====== Stat Report : ===== #")
		print "\nTotal passwords : " + str(self.count)
		print "Unique password : " + str(uniq)
		print "Longuest password : " + str(passM) + " (" + str(lenghtM) + " characters)"
		print "Smallest password : " + str(lenghtm) + " characters"
		print "Only Num : " + str(onlyNum)
		print "Only Special Char : " + str(speChar)
		print "Only Alpha : " + str(onlyAlpha)
		print "Only Upper Case : " + str(onlyUpper)
		print "Only Lower Case : " + str(onlyLowAlpha)
		if source != "":
			print "Containing " + source +" : " + str(sourceC)
		print "Equal or contain one of the 25 worst 2011 password : " + str(wp) 
		print "Close to the 25 worst 2011 password : " + str(wpProx)
		if mode == 1:
			print "Username = Password : " + str(uEqP)
			print "Username ~ Password : " + str(uEqPProx)





		print("\nMost Use Top "+str(top))
		i 	= 1
		for key, value in sorted(topP.items(), key=itemgetter(1), reverse=True):
			print str(i) + ": " + str(key) + " = " + str(value[0]) + " ("+ str(value[1]) + "%)"
			i	+= 1
		print "Common passwords represent " + str(wpp) + "% of the list"





		print "\n Password lenght distribution: "
		for key in topL.keys():
			a = int(topL[key][1])
			b = ""
			for i in range (0,a):
				b += "="
			print "+---------------|-------------------------------|"
			print "|" + str(key) + " characters \t|" + str(topL[key][0]) + "\t ("+ str(topL[key][1]) + "%) \t| "  + b 
		print "+---------------|-------------------------------|"
		print str(lpp) + "% passwords have at leat 8 characters"






		print "\nNumbers of Special Char : "
		for key in topS.keys():
			print str(key) + " specials characters : " + str(topS[key][0]) + " ("+ str(topS[key][1]) + "%)"
		print str(sp) + "% passwords have at leat 3 specials characters"


#---------------------------------------------#	
#		   MAIN			      #
#---------------------------------------------#	
	def main(self):
		argTab = p.getargs()
		#argTab = [filename, mode, separator, source, top]
		if argTab == EXIT_ON_MODE:
			print "Invalid mode : please check -h or --help. "
			exit()
		if argTab == EXIT_ON_SEPARATOR:
			print "Separator error [--mode 1] require a separator. Please check -h or --help. "
			exit()
		p.load(argTab[0],argTab[1],argTab[2])
		p.stat(argTab[1],argTab[3],argTab[4])





if __name__ == "__main__":
	p = pasta()
	p.main()

