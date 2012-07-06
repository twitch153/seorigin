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
def labelHelp():
        print("Labels: ")
        print("========\n")
        print("   Label classes: ")
        print("   ===============")
        print("   Label classes are separate by five classes: type label, class label, and\n   string label.")
        print("   When inserting labels into SEorigin's database we consider the label class as\n   an integer.\n")
        print("   Integer types are as follows: ")
        print("   0 = Type label\n   1 = Object Label\n   2 = Privilege label")
        print("   3 = String label\n   4 = Argument label\n")
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
    defOutFile = os.path.join(os.environ["PWD"], 'seorigin') # Default output location.

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
            labelHelp()
            sys.exit()

# Sanity check to make sure the parsed information is getting written to some location.
    if inputCheck:
        inputFile=defInFile
        print ("\nInput location not specified, defaulting to: " + defInFile)
    if outputCheck:
        outputFile=sqlite3.connect(defOutFile) # Creates a connection to the sqlite3 database
        print ("\nOutput location not specified, defaulting to: " + defOutFile)
    return( inputFile, outputFile )
	
"""
readInput( inputFile ) reads in the specified file. If a file does not exist it will shoot an exception and print out
usage().
"""
def readInput( inputFile ):
    try:
        f=open(inputFile, 'r') # This creates the function for opening the file, and assigns it to f.
    except Exception as err:
        print("\nreadInput() Error: {0}".format(err),"\n")
        usage()
        
    fileLines = f.readlines()
    f.close()

    return fileLines

"""
getStatementType( lines ) read through the lines of the input and searches for each statement type and assigns
a certain value to each statement and then returns the value of the statement.
"""
def getStatementType( lines ):
    for line in lines:
        statementValue = 4
        if re.search('^allow', line):
            statementValue = 0
        # Checks for all interface calls, an interface is something like this: "corecmd_read_bin_symlinks($1)"
        elif re.search('^.*\(', line):
            statementValue = 1
        elif re.search('^typeattribute', line):
            statementValue = 2
        elif re.search('^dontaudit', line):
            statementValue = 3
        else:
            statementValue += 1
    return statementValue

"""
getLabelClass( labels ) read through the labels of the input and searches for each statement type and assigns
a certain value to each label and then returns the value of the label.
"""
def getLabelClass( label ):
    labelClass = 0
    if re.search('.*\_t$', label):
        labelClass = 0
    elif re.search('.*_type$', label):
        labelClass = 0
    elif re.search('.*_perms', label):
        labelClass = 2
    elif re.search('\".*\"', label):
        labelClass = 3
    elif re.search('^\$.', label):
        labelClass = 4
    else:
        labelClass = 1
    return labelClass

"""
createTables( outputFile ) creates the necessary tables for the SQLite3 database
"""
def createTables( outputFile ):
    try:
        database = outputFile.cursor()    
        database.execute('''create table if not exists tb_files
        (FileID Integer primary key AUTOINCREMENT, Filename text)''')
        database.execute('''create table if not exists tb_files
        (FileID Integer primary key AUTOINCREMENT, Filename text)''')
        database.execute('''create table if not exists tb_definitionNames 
        (DefinitionId Integer primary key AUTOINCREMENT NOT NULL, DefinitionName 
        Text NOT NULL)''')
        database.execute('''create table if not exists tb_label
        (LabelId Integer PRIMARY KEY AUTOINCREMENT NOT NULL, LabelClass INTEGER NOT NULL, 
        Name Text NOT NULL)''')
        database.execute('''create table if not exists tb_labelSet
        (LabelSetId Integer NOT NULL, LabelId NOT NULL, primary key(LabelSetID, LabelID),
        foreign key(LabelId) references tb_label(LabelId))''')
        database.execute('''create table if not exists tb_statement_declare 
        (StatementId Integer primary key AUTOINCREMENT NOT NULL, DeclarationClass Integer NOT NULL, 
        TargetId Integer NOT NULL, AliasId Integer, foreign key(TargetId) references tb_labelSet(LabelSetId), 
        foreign key(AliasId) references tb_LabelSet(LabelSetId))''')  
        database.execute('''create table if not exists tb_source
        (FileID Integer primary key AUTOINCREMENT, Line_Number text, Call_Statement text,
        Call_Arguments text)''')
    except Exception as err:
        print("\ncreateTables() Error: {0}".format(err),"\n")
        usage()
    outputFile.commit()
    database.close()

"""
cleanDefine( line ) reads in lines of the input files and "cleans" them up, removing any unnecessary new lines for
the definition records and returns them in a clean array.
"""
def cleanDefine( lines ):
    try:
        cleanDefine = []
        defineCheck = False
        for line in lines:
            #line = re.sub('## .*$', '', line) # Removes the ## <record type> record from parsed output
            if re.search('^## definition', line):
                defineCheck = True
            elif re.search('^\n', line):
                    defineCheck = False
            if defineCheck:
                line = re.sub('^# ', '', line)
                if line == '\n':
                    continue
                line = re.sub('\n', '', line)
                cleanDefine.append(line)
        return cleanDefine
    except Exception as err:
        print("\ncleanDefine() Error: {0}".format(err),"\n")
        usage()
        sys.exit() 

"""
cleanSource( line ) reads in lines of the input files and "cleans" them up, removing any unnecessary new lines for
source records and returns them in a clean array.
"""
def cleanSource( lines ):
    try:
        cleanSource = []
        sourceCheck = False
        for line in lines:
            line = re.sub('# line: ', '', line)# Removes "# line: " from input.
            if re.search('^## source', line):
                sourceCheck = True
            elif re.search('^\n', line):
                sourceCheck = False
            if sourceCheck:
                line = re.sub('^# ', '', line)
                if line == '\n':
                    continue
                line = re.sub('\n', '', line)
                cleanSource.append(line)
        return cleanSource
    except Exception as err:
        print("\ncleanSource() Error: {0}".format(err),"\n")
        usage()
        sys.exit()

"""
insertFile() writes specific information from the input file to tb_files in the seorigin db.
"""
def insertFile( outputFile, lines ):
    try:
        database = outputFile.cursor()
        # Takes the lines from the input and "cleans" them to be read in for DB instertion.
        clean_source = cleanSource( lines )
        # Makes the first defineStanza some impossible values that wouldn't be in the beginning of a source record.
        sourceStanza = ['-', '-', '-', '-', '-']
        for source in clean_source:
            if re.search('^## ', source):
                sourceFile = sourceStanza[1]
                File = (sourceFile, )
                for F in File:
                    if not re.search('^\-', F):
                        database.execute("""insert into tb_files values (NULL, ?)""", File)
                sourceStanza = []
            sourceStanza.append(source)
        # The final source record is not listed in the for-loop above so we add it in after.
        sourceFile = sourceStanza[1]
        File = (sourceFile, )
        database.execute("""insert into tb_files values (NULL, ?)""", File)
    except Exception as err:
        print("\ninsertFile() Error: {0}".format(err),"\n")
        usage()
    outputFile.commit()
    database.close()

"""
insertDefinitionNames() writes specific information from the input file to tb_definitionNames in the seorigin db.
"""
def insertDefinitionNames( outputFile, lines ):
    try:
        skipCheck = False
        database = outputFile.cursor()
        # Takes the lines from the input and "cleans" them to be read in for DB instertion.
        clean_define = cleanDefine( lines )
        # Makes the first defineStanza some impossible values. 
        defineStanza = ['@', '@', '@']
        for define in clean_define:
            if re.search('^## ', define):
                definitionCall = defineStanza[1]
                defName = (definitionCall, )
                for Name in defName:
                    if not re.search('^@', Name):
                        database.execute("""insert into tb_definitionNames values (NULL,?)""", defName)
                defineStanza = [] 
            defineStanza.append(define)
        # The final source record is not listed in the for-loop above so we add it in after.
        definitionCall = defineStanza[1]
        defName = (definitionCall, )
        database.execute("""insert into tb_definitionNames values (NULL,?)""", defName)
    except Exception as err:
        print("\ninsertDefinitionNames() Error: {0}".format(err),"\n")
        usage()
    outputFile.commit()
    database.close()
"""
insertinsertLabel() writes specific information from the input file to tb_label in the seorigin db.
"""
def insertLabel( outputFile, lines ):
    try:
        database = outputFile.cursor()
        labelCheck = False
        allowCheck = False
        for line in lines:
            if re.search('^allow.*$', line):
                allowCheck = True
            elif re.search('^\n', line):
                allowCheck = False
            if allowCheck:
                line = re.sub('^\s+', '', line)
                labels = re.sub('allow ', '', line)
                labels = re.sub('optional_policy.*$', '', labels)
                labels = re.sub('tunable_policy.*$', '', labels)
                labels = re.sub(':', ' ', labels)
                labels = re.sub('dontaudit', '', labels)
                labels = re.sub('\'', '', labels)
                labels = re.sub('{.*}', '', labels)
                labels = re.sub('^.*\(', '', labels)
                labels = re.sub('\)', '', labels)
                labels = re.sub(';', '', labels)
                labels = re.sub(',', ' ', labels)
                label = labels.split()
                for lab in label:
                    labelClass = getLabelClass(lab)
                    l = (labelClass, lab)
                    database.execute('''insert into tb_label values (NULL, ?, ?)''', l)
            if re.search('^.*\(', line):
                labelCheck = True
            elif re.search('[.*\)\n\)]', line):
                labelCheck = False
            if labelCheck:
                line = re.sub('^\s+', '', line)
                labels = re.sub('optional_policy.*$', '', line)
                labels = re.sub('tunable_policy.*$', '', labels)
                labels = re.sub('genfscon.*$', '', labels)
                labels = re.sub('^if.*$', '', labels)
                labels = re.sub('^\w*', '', labels)
                labels = re.sub('[\(\)]', '', labels)
                labels = re.sub('{.*}', '', labels)
                labels = re.sub('[,, ]', ' ', labels)
                labels = re.sub('\n*', '', labels)
                label = labels.split()
                for lab in label:
                    labelClass = getLabelClass(lab)
                    l = (labelClass, lab)
                    database.execute('''insert into tb_label values (NULL, ?, ?)''', l)
    except Exception as err:
        print("\ninsertLabel() Error: {0}".format(err),"\n")
        usage()
    outputFile.commit()
    database.close()

"""
insertinsertLabelSet() writes specific information from the input file to tb_labelset in the seorigin db.
"""
def insertLabelSet( outputFile, lines ):
    try:
        database = outputFile.cursor()
        setCheck = False
        labelSetId = 0
        cleanSet = ['']
        for line in lines:
            if re.search('^.*\(.*{', line):
                labelSets = re.sub('^if.*$', '', line)
                labelSets = re.sub('^.*\(', '', labelSets)
                labelSets = re.sub('\)', '', labelSets)
                labelSets = re.sub('\n', '', labelSets)
                labelSet = labelSets.split(",")
                for Set in labelSet:
                    Set = re.sub('^\w*', '', Set)
                    Set = re.sub('^ \w*', '', Set)
                    Set = re.sub('^\$\d+.*$', '', Set)
                    Set = re.sub('^ {', '{', Set)
                    Set = re.sub('\n', '', Set)
                    Set = re.sub('^ $', '', Set)
                    if Set == '':
                        continue
                    cleanSet.append(Set) # Cleans the list of label sets which will be used to search for duplicates.
        cleanSet = list(set(cleanSet)) # Makes the list without any duplicates.
        for clean in cleanSet:
            if clean == '':
                continue
            else:
                labelSetId += 1
           # database.execute('''insert into tb_labelSet values(?,?)''', labelSet)
    except Exception as err:
        print("\ninsertLabelSet() Error: {0}".format(err),"\n")
        usage()
    outputFile.commit()
    database.close()

"""
insertStatementDeclare()
"""
def insertStatementDeclare( outputFile, lines ):
    try:
        database = outputFile.cursor()
        for line in lines:
            print("Banana")        
        database.execute('''insert into tb_Statement_Declare values(NULL,?,NULL,NULL)''', DeclarationClass)
    except Exception as err:
        print("\ninsertStatementDeclare() Error: {0}".format(err),"\n")
        usage()
    outputFile.commit()
    database.close()
"""
writeDefineDB( outputFile, output) grabs parsed output, and writes definition record data to SQLite3 database (output).
"""
def writeDefineDB( outputFile, lines ):
    try:
        skipCheck = False
        database = outputFile.cursor()
        clean_define = cleanDefine( lines )
        # Makes the first defineStanza some impossible values. 
        defineStanza = ['@', '@', '@']
        for define in clean_define:
            if re.search('^## ', define):
                definitionCall = defineStanza[1]
                definitionList = defineStanza[2:]
                for definition in definitionList:
                    define = [definitionCall, definition]
                    for d in define:
                        if re.search('^@', d):
                            skipCheck = True
                        else:
                            skipCheck = False
                    if not skipCheck:
                        pass
                        #database.execute("""insert into tb_definition values (?,?)""", define)
                defineStanza = [] 
            defineStanza.append(define)
        # The final source record is not listed in the for-loop above so we add it in after.
        definitionCall = defineStanza[1]
        definitionList = defineStanza[2:]
        for definition in definitionList:
            define = [definitionCall, definition]
            #database.execute("""insert into tb_definition values (?,?)""", define)
    except Exception as err:
        print("\nError: {0}".format(err),"\n")
        usage()
    outputFile.commit()
    database.close()

"""
insertSource( outputFile, output) grabs parsed output, and writes source record data to SQLite3 database (output).
"""
def insertSource( outputFile, lines ):
    try:
        database = outputFile.cursor()
        clean_source = cleanSource( lines )
        # Makes the first defineStanza some impossible values that wouldn't be in the beginning of a source record.
        sourceStanza = ['-', '-', '-', '-', '-']
        for source in clean_source:
            if re.search('^## ', source):
                sourceFile = sourceStanza[1]
                sourceLine = sourceStanza[2]
                sourceCall = sourceStanza[3]
                sourceCallArgs = sourceStanza[4]
                sourceRecord = [sourceLine, sourceCall, sourceCallArgs]
                File = (sourceFile, )
                for F in File:
                    if not re.search('^\-', F):
                        database.execute("""insert into tb_files values (NULL, ?)""", File)
                if not re.search('^\-', sourceLine):
                    database.execute("""insert into tb_source
                    values (NULL, ?, ?, ?)""", sourceRecord)
                sourceStanza = []
            sourceStanza.append(source)
        # The final source record is not listed in the for-loop above so we add it in after.
        sourceFile = sourceStanza[1]
        sourceLine = sourceStanza[2]
        sourceCall = sourceStanza[3]
        sourceCallArgs = sourceStanza[4]
        File = (sourceFile, )
        source = [sourceLine, sourceCall, sourceCallArgs]
        database.execute("""insert into tb_files values (NULL, ?)""", File)
        database.execute("""insert into tb_source values (NULL, ?,?,?)""", source)
    except Exception as err:
        print("\ninsertSource() Error: {0}".format(err),"\n")
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

writeOut('/home/twitch153/seorigin/debug.txt', output)
"""
def writeOut( outputFile, output ):
    try:
        parsedOut = open(outputFile, 'w') # This assigns a new file to parsedOut
    except Exception as err:
        print("\n\nwriteOut() Error: {0}".format(err),"\n\n")
        usage()

    parsedOut.write(output)
    parsedOut.close()

"""
seorigin( outputFile, lines ) creates the seorigin database by calling the necessary functions to 
create and write the seorigin database.
"""
def seorigin( outputFile, lines ):
    try:
        createTables( outputFile )
        insertFile( outputFile, lines )
        insertDefinitionNames(  outputFile, lines )
        insertLabel( outputFile, lines )
        insertLabelSet( outputFile, lines )
        #insertSource( outputFile, lines )
    except Exception as err:
        print("seorigin() Error: {0}".format(err),"\n")
        usage()

"""
main() is where all the magic happens!Like Disney land, just less...'cartooney'.
"""
def main():
    print("Workflow component v1.1.4: ")
    (inputFile, outputFile) = parse_cmd_args()
    lines = readInput( inputFile )
    seorigin( outputFile, lines )

"""
The main function is run below.
"""
if __name__ == "__main__":
    main()
