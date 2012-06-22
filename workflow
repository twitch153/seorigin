#!/usr/bin/env python

import sys, getopt, re, os, sqlite3

"""
================================================================================
=
=   This file is part of seorigin
=  Copyright (C) 2012  Devan Franchini, Anthony G. Basile, Sven Vermeulen
=
=  seorigin is free software: you can redistribute it and/or modify
=  it under the terms of the GNU General Public License as published by
=  the Free Software Foundation, either version 3 of the License, or
=
=  seorigin is distributed in the hope that it will be useful,
=  but WITHOUT ANY WARRANTY; without even the implied warranty of
=  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
=  GNU General Public License for more details.
=
=  You should have received a copy of the GNU General Public License
=  along with seorigin.  If not, see <http://www.gnu.org/licenses/>.
=
=  ----
= policy-parser.py is the parsing component of seorigin, the SELinux Policy originator.
=
= Purpose:
= The parser takes the m4 marco expansion of SELinux policies and parses it into a suitable and
= useful manner for the workflow component of the policy originator to database.
= 
= See README for more information.
=
================================================================================
"""

def usage():
	print("Proper usage:\nworkflow -i(--input) [file to parse] -o(--output) [database location to ouput to]")

"""
parse_cmd_agrs() sets up the -i -o and -h flags for the policy-parser script. See usage for what each flag is.
"""
def parse_cmd_args():
    shortOpts = 'i:o:h'
    longOpts = ['input=','output=','help']

    opts, extraparams = getopt.getopt(sys.argv[1:], shortOpts, longOpts)
    
    inputCheck = True    # Boolean check to see if input location has been set.
    outputCheck = True   # Boolean check to see if output location has been set.
    defInFile = os.path.join(os.environ["PWD"], 'parsed_output.txt') # Default input location.
    defOutFile = os.path.join(os.environ["PWD"], 'record_database') # Default output location.

    #Set up arguement flags for script execution.
    for o, p in opts:
        if o in ['-i', '--input']:
            inputFile=p
            inputCheck = False
        elif o in ['-o', '--output']:
            outputFile = sqlite3.connect(os.path.join(os.environ["PWD"], p))
            outputCheck=False
        elif o in ['-h', '--help']:
            usage()

# Sanity check to make sure the parsed information is getting written to some location.
    if outputCheck:
        outputFile=sqlite3.connect(defOutFile)
        print ("\nOutput location not specified, defaulting to: " + defOutFile)
    if inputCheck:
        inputFile=defInFile
        print ("\nInput location not specified, defaulting to: " + defInFile)
    return( inputFile, outputFile )
	
"""
readInput( inputFile ) reads in the specified file. If a file does not exist it will shoot an exception and print out
usage().
"""
def readInput( inputFile ):
    try:
        f=open(inputFile, 'r') # This creates the function for opening the file, and assigns it to f.
    except Exception as err:
        print("\n Error: {0}".format(err),"\n")
        usage()
        
    fileLines = f.readlines()
    f.close()

    return fileLines
def parseRecords( lines ):
    sourceRecordCheck = False
    definitionRecordCheck = False
    for line in lines:
        if re.search('## source', line):
            sourceRecordCheck = True
        elif re.search('^\n', line):
            sourceRecordCheck = False
        if sourceRecordCheck:
            line = re.sub('## source record \d+', '', line)
            sourceCall = re.sub('^#.*$', '', line)
            sourceCall = re.sub('\n', '', sourceCall)
            sourceCall = re.sub('\(.*\)', '', sourceCall)
            sourceCallArgs = re.sub('^\w*', '', line)
            sourceCallArgs = re.sub('^#.*$', '', sourceCallArgs)
            sourceFile = re.sub('^\w*', '', line)
            sourceFile = re.sub('^# ', '', sourceFile)
            sourceFile = re.sub('\(.*\)', '', sourceFile)
            sourceFile = re.sub('^\s+', '', sourceFile)
            sourceLineNum = re.sub('\w+/', '', sourceFile) 
            sourceLineNum = re.sub('\w+\.te:', '', sourceLineNum)
            sourceFile = re.sub(':\d+', '', sourceFile)

            print("File: " + sourceFile)
            print("Line Number: " + sourceLineNum)     
            print("Call statement: " + sourceCall)
            print("Call arguments: " + sourceCallArgs)

"""
writeOut( outputFile, output) writes output to the file we want to have it outputted to.
"""
def writeOut( outputFile ):
    try:
        database = outputFile.cursor() # This assigns a new file to parsedOut
    except Exception as err:
        print("Error: {0}".format(err),"\n")
        usage()

    database.close()
def main():
    (inputFile, outputFile) = parse_cmd_args()
    lines = readInput( inputFile )
    parseRecords( lines )
    #output = parseFile( lines )
    writeOut( outputFile )

"""
The main function is run below.
"""
if __name__ == "__main__":
    main()
