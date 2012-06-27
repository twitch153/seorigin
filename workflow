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
	print("Proper usage:\nworkflow -i(--input) [file to parse] -o(--output) [database location]")

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
            outputFile = sqlite3.connect(p)
            outputCheck=False
        elif o in ['-h', '--help']:
            usage()

# Sanity check to make sure the parsed information is getting written to some location.
    if outputCheck:
        outputFile=sqlite3.connect(defOutFile) # Creates a connection to the sqlite3 database
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

"""
writedatabase( outputFile, output) grabs parsed output, and writes necessary data to SQLite3 database
"""
def writeDatabase( outputFile, lines ):
    try:
        database = outputFile.cursor()
        # Create TB_SOURCE table
        database.execute('''create table if not exists tb_source
        (Filename text, Line_Number text, Call_Statement text, 
        Call_Arguments text, primary key( Filename, Line_Number ))''')
        # Create TB_Definition table
        database.execute('''create table if not exists tb_definition
        (Call text, Definition text)''')
        outputFile.commit()

        cleanSource = []
        cleanDefine = []
        defineCheck = False
        sourceCheck = False
        for line in lines:
            #line = re.sub('## .*$', '', line) # Removes the ## <record type> record from parsed output
            if re.search('^## definition record \d+', line):
                defineCheck = True
            elif re.search('^## source ', line):
                sourceCheck = True
            elif re.search('^\n', line):
                sourceCheck = False
                defineCheck = False

            if sourceCheck:
                line = re.sub('^# ', '', line)
                if line == '\n':
                    continue

                line = re.sub('\n', '', line)
                cleanSource.append(line)

            if defineCheck:
                line = re.sub('^# ', '', line)
                if line == '\n':
                    continue

                line = re.sub('\n', '', line)
                cleanDefine.append(line)

        # Makes the first defineStanza some impossible values that wouldn't be in the 
        #beginning of a source record.
        sourceStanza = ['-', '-', '-', '-', '-']
        for source in cleanSource:
            if re.search('^## ', source):
                sourceFile = sourceStanza[1]
                sourceLine = sourceStanza[2]
                sourceCall = sourceStanza[3]
                sourceCallArgs = sourceStanza[4]
                sourceRecord = [sourceFile, sourceLine, sourceCall, sourceCallArgs]
                for r in sourceRecord:
                    if not re.search('^\-', r):
                        try:
                            database.execute("""insert into tb_source
                            values (?,?,?,?)""", sourceRecord)
                        # Attempts to find multiple entries and skip them prior to
                        # inserting them into tb_source.
                        except sqlite3.IntegrityError:
                            pass

                sourceStanza = []

            sourceStanza.append(source)
        # The final source record is not listed in the for-loop above so we add it in after.
        sourceFile = sourceStanza[1]
        sourceLine = sourceStanza[2]
        sourceCall = sourceStanza[3]
        sourceCallArgs = sourceStanza[4]
        source = [sourceFile, sourceLine, sourceCall, sourceCallArgs]
        try:
                database.execute("""insert into tb_source values (?,?,?,?)""", source)
        except sqlite3.IntegrityError:
            pass

        # Makes the first defineStanza some impossible values. 
        defineStanza = ['@', '@', '@']
        for define in cleanDefine:
            if re.search('^## ', define):
                definitionCall = defineStanza[1]
                definitionList = defineStanza[2:]
                for definition in definitionList:
                    define = [definitionCall, definition]
                    for i in define:
                        if not re.search('^\@', i):
                            try:
                                #pass # stub for now till we get proper insertion of definition record
                                database.execute("""insert into tb_definition values (?,?)""", define)
                        # Attempts to find multiple entries and skip them prior to
                        # inserting them into tb_definition. Still need to properly insert definition first.
                            except sqlite3.IntegrityError:
                                pass

                    defineStanza = [] 
            defineStanza.append(define)

        # The final source record is not listed in the for-loop above so we add it in after.
        definitionCall = defineStanza[1]
        definitionList = defineStanza[2:]
        for definition in definitionList:
            define = [definitionCall, definition]
            try:
                database.execute("""insert into tb_definition values (?,?)""", define)
            except sqlite3.IntegrityError:
                pass


    except Exception as err:
        print("Error: {0}".format(err),"\n")
        usage()

    outputFile.commit()
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
    #writeOut('/home/twitch153/seorigin/debug.txt', output)
    writeDatabase( outputFile, lines )

"""
The main function is run below.
"""
if __name__ == "__main__":
    main()
