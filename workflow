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

def parseDefinitionRecords( lines ):
    definitionRecordCheck = False
    definitionCall = ''
    definition = ''
    for line in lines:
        if re.search('## definition', line):
            definitionRecordCheck = True            
        elif re.search('\n\n', line):
            definitionRecordCheck = False
        if definitionRecordCheck:
            line = re.sub('## definition record \d+', '', line)
            line = re.sub('\n', '', line)
            if re.search('^\w*$', line):
                continue
            definitionCall = re.sub('^\w.*$', '', line)
            definitionCall = re.sub('# ', '', definitionCall)
            definition = re.sub('^# ', '', line)
            definition = re.sub('^\w+$', '', definition)
            definitionRecord = [definitionCall, definition]
            cleanDefinition = []
            for d in definitionRecord:
                if d == '':
                    continue
                cleanDefinition.append(d)
                #print(cleanDefinition)

def parseSourceRecords( lines ):
    sourceRecordCheck = False
    for line in lines:
        if re.search('## source', line):
            sourceRecordCheck = True
        elif re.search('^\n', line):
            sourceRecordCheck = False
        if sourceRecordCheck:
            line = re.sub('## source record \d+', '', line)
            line = re.sub('\n', '', line)
            sourceCall = re.sub('^#.*$', '', line)
            sourceCallArgs = re.sub('^\w*', '', sourceCall)
            sourceCall = re.sub('\(.*\)', '', sourceCall)
            sourceFile = re.sub('^\w*', '', line)
            sourceFile = re.sub('^# ', '', sourceFile)
            sourceFile = re.sub('\(.*\)', '', sourceFile)
            sourceFile = re.sub('^\s+', '', sourceFile)
            sourceLineNum = re.sub('\w+/', '', sourceFile) 
            sourceLineNum = re.sub('\w+\.te:', '', sourceLineNum)
            sourceFile = re.sub(':\d+', '', sourceFile)
            sourceFile = re.sub('\n', '', sourceFile)
            if re.search('^\w*$', line):
                continue
            if line == '':
                continue
            sourceRecord = [sourceFile, sourceLineNum, sourceCall, sourceCallArgs]
            cleanSource = []
            for s in sourceRecord:
                if s == '':
                    continue
                cleanSource.append(s)
                #print(cleanSource)

    #return sourceRecord

"""
writedatabase( outputFile, output) grabs parsed output, and writes necessary data to SQLite3 database
"""
def writeDatabase( outputFile, source, definition ):
    try:
        database = outputFile.cursor() # This creates a cursor object for the database.
        # Create TB_SOURCE table
        #database.execute("""create table TB_SOURCE
        #(Filename, Line_Number, Call_Statement, 
        #Call_Arguments)""")
        # Create TB_Definition table
        #database.execute("""create table TB_DEFINITION
        #(Call, Definition)""")
    except Exception as err:
        print("Error: {0}".format(err),"\n")
        usage()
    database.close()

"""
writeOut( outputFile, output) writes output to the file we want to have it outputted to. This will be included
for debugging purposes. 

To debug: 

In parseRecords():
create string output = '' at beginning of function
at the end of the function *inside* the for-loop assign whatever variable you would like as output += <variable>
at the end of the function *outside* of the for-loop return output
In main():
use function writeOut( outputFile, output )
outputFile being the location of where you would like the file to be located.

This will write the output of the parsing to where you would like it to be located.
"""
def writeOut( outputFile, output ):
    try:
        parsedOut = open(outputFile, 'w') # This assigns a new file to parsedOut
    except Exception as err:
        print("\n\nError: {0}".format(err),"\n\n")
        usage()

    parsedOut.write(output)
    parsedOut.close()

def main():
    (inputFile, outputFile) = parse_cmd_args()
    lines = readInput( inputFile )
    definition = parseDefinitionRecords( lines )
    source = parseSourceRecords( lines ) 
    #writeOut('/home/twitch153/seorigin/debug.txt', output)
    writeDatabase( outputFile, source, definition )

"""
The main function is run below.
"""
if __name__ == "__main__":
    main()
