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
        print("   1 = Type label\n   2 = Attribute Label\n   3 = Classes label\n   4 = Privilege label")
        print("   5 = String/File label\n   6 = Argument label\n   7 = Role label\n")
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
def getStatementType( line ):
    statementValue = 69
    # Checks for record lines.
    line = re.sub('^\s+', '', line)
    if re.search('#', line):
        pass
    elif re.search('^}', line):
        pass
    elif re.search('tunable_policy', line):
        pass
    elif re.search('^{', line):
        pass
    elif re.search('^allow', line):
        statementValue = 0
    # Checks for all interface calls"
    elif re.search('^.*\(', line):
        statementValue = 1
    elif re.search('^typeattribute', line):
        statementValue = 2
    elif re.search('^dontaudit', line):
        statementValue = 3
    elif re.search('type .*', line):
        statementValue = 4
    elif re.search('types .*', line):
        statementValue = 4
    elif re.search('role .*', line):
        statementValue = 4
    else:
        pass
        #print('Unknown line: ' + line)
    return statementValue

"""
labelsToList( line ) gets the labels from a specific line and returns the labels parsed out from the line as a list of
the labels of that line.
"""
def labelsToList( line ):
    try:

        labels = ''
        statementCheck = False
        interfaceCheck = False
        setCheck = False
        if getStatementType(line) == 0:
            statementCheck = True
        elif getStatementType(line) == 2:
            statementCheck = True
        elif getStatementType(line) == 3:
            statementCheck = True
        elif getStatementType(line) == 4:
            statementCheck = True
        elif re.search('^\n', line):
            statementCheck = False

        if re.search('^.*\(', line):
            interfaceCheck = True
        elif re.search('[.*\)\n\)]', line):
            labelCheck = False
        if statementCheck:
            line = re.sub('^\s+', '', line)
            labels = re.sub('^\w+ ', '', line)
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
            labels = re.sub('~', '', labels)

        if interfaceCheck:
            line = re.sub('^\s+', '', line)
            labels = re.sub('optional_policy.*$', '', line)
            labels = re.sub('tunable_policy.*$', '', labels)
            labels = re.sub('genfscon.*$', '', labels)
            labels = re.sub('^if.*$', '', labels)
            labels = re.sub('^\w*', '', labels)
            labels = re.sub('[\(\)]', '', labels)
            labels = re.sub('{.*}', '', labels)
            labels = re.sub('~', '', labels)
            labels = re.sub('[,, ]', ' ', labels)
            labels = re.sub('\n*', '', labels)

        labels = labels.split()
        return labels
    except Exception as err:
        print("\nlabelsToList() Error: {0}".format(err),"\n")

"""
labelSetToList( line ) gets the label set from a specific line and returns the labels parsed out from the line as a list of
the labels of that line.
"""
def labelSetToList( line ):
    try:
        Set = ''
        setCheck = False
        if re.search('.*{', line):
            setCheck = True
        elif re.search('}', line):
            setCheck = False
        if setCheck:
            labelSets = re.sub('^if.*$', '', line)
            labelSets = re.sub('^.*\(', '', labelSets)
            labelSets = re.sub('^}.*$', '', labelSets)
            labelSets = re.sub('\)', '', labelSets)
            labelSets = re.sub(',', '%', labelSets)
            labelSets = re.sub('{.*%}', ',', labelSets)
            labelSets = re.sub('\n', '', labelSets)
            labelSet = labelSets.split("%")
            for Set in labelSet:
                Set = re.sub('^\w*', '', Set)
                Set = re.sub('^ \w*', '', Set)
                Set = re.sub('^\$\d+.*$', '', Set)
                if re.search('~{', Set):
                    Set = re.sub('.*~{', '~{', Set)
                else:
                    Set = re.sub('.*{', '{', Set)
                Set = re.sub('}.*$', '}', Set)
                Set = re.sub('\n', '', Set)
                Set = re.sub('^ $', '', Set)
                Set = re.sub('[{}]', '', Set)
                Set = re.sub('^ ', '', Set)
                Set = Set.split()
        return Set
    except Exception as err:
        print("\nlabelSetToList() Error: {0}".format(err),"\n")

"""
getClassList() grabs the information from "SELinux Class list" and returns it as a list.
"""
def getClassList():
    classList = readInput(os.path.join(os.environ["PWD"], 'SELinux_Class_list.txt'))
    result = ['']
    for List in classList:
        List = re.sub('\n', '', List)
        result.append(List)
    return result
    
"""
getPermsList() grabs the information from "SELinux Perms list" and returns it as a list.
"""
def getPermsList():
    permsList = readInput(os.path.join(os.environ["PWD"], 'SELinux_Perms_list.txt'))
    result = ['']
    for List in permsList:
        List = re.sub('\n', '', List)
        result.append(List)
    return result

"""
getLabelClass( labels ) read through the labels of the input and searches for each statement type and assigns
a certain value to each label and then returns the value of the label.
"""
def getLabelClass( label, classList, permsList ):
    labelClass = 1
    if label in classList:
        labelClass = 3
    elif label in permsList:
        labelClass = 4
    elif re.search('.*_perms', label):
        labelClass = 4
    elif re.search('.*\_t$', label):
        labelClass = 1
    elif re.search('.*_type$', label):
        labelClass = 1
    elif re.search('\".*\"', label):
        labelClass = 5
    elif re.search('^\$.', label):
        labelClass = 6
    elif re.search('._*\_r$', label):
        labelClass = 7
    else:
        labelClass = 2
    return labelClass

"""
createTables( outputFile ) creates the necessary tables for the SQLite3 database
"""
def createTables( outputFile ):
    try:
        database = outputFile.cursor() 
        database.execute('''PRAGMA foreign_keys=OFF''')   
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

        database.execute('''create table if not exists tb_statement_allow
        (StatementId INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, SourceId INTEGER NOT NULL, 
        SourceModifier INTEGER NOT NULL, TargetId INTEGER NOT NULL, TargetModifier INTEGER NOT NULL, 
        ClassesId INTEGER NOT NULL, ClassesModifier INTEGER NOT NULL, PrivilegeId INTEGER NOT NULL, 
        PrivilegeModifier INTEGER NOT NULL, FOREIGN KEY(SourceId) REFERENCES TB_LABELSET(LabelSetId), 
        FOREIGN KEY(TargetId) REFERENCES TB_LABELSET(LabelSetId), FOREIGN KEY(ClassesId) 
        REFERENCES TB_LABELSET(LabelSetId), FOREIGN KEY(PrivilegeId) REFERENCES TB_LABELSET(LabelSetId))''')

        database.execute('''create table if not exists tb_statement_interface
        (StatementId INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, InterfaceId INTEGER NOT NULL, 
        Arg1LabelId INTEGER NOT NULL, Arg2LabelId INTEGER, Arg3LabelId INTEGER, Arg4LabelId INTEGER, 
        Arg5LabelId INTEGER, FOREIGN KEY(InterfaceId) REFERENCES TB_DEFINITIONNAMES(DefinitionId), 
        FOREIGN KEY(Arg1LabelId) REFERENCES TB_LABELSET(LabelSetId), FOREIGN KEY(Arg2LabelId) 
        REFERENCES TB_LABELSET(LabelSetId), FOREIGN KEY(Arg3LabelId) REFERENCES TB_LABELSET(LabelSetId), 
        FOREIGN KEY(Arg4LabelId) REFERENCES TB_LABELSET(LabelSetId), FOREIGN KEY(Arg5LabelId) 
        REFERENCES TB_LABELSET(LabelSetId))''')

        database.execute('''create table if not exists tb_statment_assign
        (StatementId INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, AssignationType INTEGER NOT NULL, 
        TargetLabelId INTEGER NOT NULL, AssignedLabelId INTEGER NOT NULL, 
        FOREIGN KEY(TargetLabelId) REFERENCES TB_LABELSET(LabelSetId), FOREIGN KEY(AssignedLabelId) 
        REFERENCES TB_LABELSET(LabelSetId))''')

        database.execute('''create table if not exists tb_definition_content
        (DefinitionId INTEGER NOT NULL, StatementDeclareId INTEGER, StatementAllowId INTEGER, 
        StatementInterfaceId INTEGER, StatementAssignId INTEGER, FOREIGN KEY(DefinitionId) 
        REFERENCES TB_DEFINITIONNAMES(DefinitionId), FOREIGN KEY(StatementDeclareId) 
        REFERENCES TB_STATEMENT_DECLARE(StatementId), FOREIGN KEY(StatementAllowId) 
        REFERENCES TB_STATEMENT_ALLOW(StatementId), FOREIGN KEY(StatementInterfaceId) 
        REFERENCES TB_STATEMENT_INTERFACE(StatementId), FOREIGN KEY(StatementAssignId) 
        REFERENCES TB_STATEMENT_ASSIGN(StatementId))''')

        database.execute('''create table if not exists tb_source 
        (FileId INTEGER NOT NULL, LineNumber INTEGER NOT NULL, StatementDeclareId INTEGER, 
        StatementAllowId INTEGER, StatementInterfaceId INTEGER, StatementAssignId INTEGER, 
        FOREIGN KEY(StatementDeclareId) REFERENCES TB_STATEMENT_DECLARE(StatementId), 
        FOREIGN KEY(StatementAllowId) REFERENCES TB_STATEMENT_ALLOW(StatementId), 
        FOREIGN KEY(StatementInterfaceId) REFERENCES TB_STATEMENT_INTERFACE(StatementId), 
        FOREIGN KEY(StatementAssignId) REFERENCES TB_STATEMENT_ASSIGN(StatementId))''')

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
                database.execute('''select * from tb_files where Filename = ?''', File)
                postPopCheck = database.fetchone()
                if postPopCheck == None:
                    for F in File:
                        if not re.search('^\-', F):     
                            database.execute("""insert into tb_files values (NULL, ?)""", File)
                else:
                    pass
                sourceStanza = []
            sourceStanza.append(source)
        # The final source record is not listed in the for-loop above so we add it in after.
        sourceFile = sourceStanza[1]
        File = (sourceFile, )
        database.execute('''select * from tb_files where Filename = ?''', File)
        postPopCheck = database.fetchone()
        if postPopCheck == None:
            database.execute("""insert into tb_files values (NULL, ?)""", File)           
        else:
            pass
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
                database.execute('''select * from tb_definitionNames where DefinitionName = ?''', defName)
                postPopCheck = database.fetchone()
                if postPopCheck == None:
                    for Name in defName:
                        if not re.search('^@', Name):
                            database.execute("""insert into tb_definitionNames values (NULL,?)""", defName)
                    else:
                        pass
                defineStanza = [] 
            defineStanza.append(define)
        # The final source record is not listed in the for-loop above so we add it in after.
        definitionCall = defineStanza[1]
        defName = (definitionCall, )
        database.execute('''select * from tb_definitionNames where DefinitionName = ?''', defName)
        postPopCheck = database.fetchone()
        if postPopCheck == None:
            database.execute("""insert into tb_definitionNames values (NULL,?)""", defName)
        else:
            pass
    except Exception as err:
        print("\ninsertDefinitionNames() Error: {0}".format(err),"\n")
        usage()
    outputFile.commit()
    database.close()

"""
insertLabel() writes specific information from the input file to tb_label in the seorigin db.
"""
def insertLabel( outputFile, lines, classList, permsList ):
    try:
        database = outputFile.cursor()
        selfCheck = ''
        for line in lines:
            labels = labelsToList(line)
            for label in labels:
                currentLabel = label
                if currentLabel == 'self':
                    label = selfCheck
                else:
                    selfCheck = currentLabel
                labelClass = getLabelClass(label, classList, permsList)
                labelCheck = (label, )
                database.execute('''select * from tb_label where Name = ?''', labelCheck)
                l = (labelClass, label)
                # Goes through each row in the database for the specific data and checks it against
                # the database, if it returns: "None" then insert the data.
                postPopCheck = database.fetchone()
                if postPopCheck == None:
                    database.execute('''insert into tb_label values (NULL, ?, ?)''', l)
                else:
                    pass
    except Exception as err:
        print("\ninsertLabel() Error: {0}".format(err),"\n")
        usage()
    outputFile.commit()
    database.close()

"""
insertLabelSet() writes specific information from the input file to tb_labelset in the seorigin db.
"""
def insertLabelSet( outputFile, lines, classList, permsList):
    try:
        database = outputFile.cursor()
        for line in lines:
            labelSet = labelSetToList(line)
            for label in labelSet:
                currentLabel = label
                if currentLabel == 'self':
                    label = selfCheck
                else:
                    selfCheck = currentLabel
                labelClass = getLabelClass(label, classList, permsList)
                labelCheck = (label, )
                database.execute('''select * from tb_label where Name = ?''', labelCheck)
                l = (labelClass, label)
                postPopCheck = database.fetchone()
                if postPopCheck == None:
                    database.execute('''insert into tb_label values(NULL, ?, ?)''', l)
                else:
                    pass
            #database.execute('''insert into tb_labelSet values(?,?)''', labelSetId)
    except Exception as err:
        print("\ninsertLabelSet() Error: {0}".format(err),"\n")
        usage()
    outputFile.commit()
    database.close()

"""
insertStatementDeclare()
"""
def insertStatementTables( outputFile, lines ):
    try:
        database = outputFile.cursor()
        for line in lines:
            if re.search('^\n', line):
                continue
            StatementType = getStatementType(line)
            # If we find an allow statement
            if StatementType == 0:
                pass
            # If we find an interface call
            if StatementType == 1:
                pass
            # If we find a typeattribute statement
            if StatementType == 2:
                pass
            # If we find a dontaudit statement
            if StatementType == 3:
                pass
            # If we find a declaration
            if StatementType == 4:
                pass
                #database.execute('''insert into tb_Statement_Declare values(NULL,?,NULL,NULL)''', DeclarationClass)
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
        classList = getClassList()
        permsList = getPermsList()
        createTables( outputFile )
        insertFile( outputFile, lines )
        insertStatementTables( outputFile, lines )
        insertDefinitionNames(  outputFile, lines )
        insertLabel( outputFile, lines, classList, permsList )
        insertLabelSet( outputFile, lines, classList, permsList )
    except Exception as err:
        print("seorigin() Error: {0}".format(err),"\n")
        usage()

"""
main() is where all the magic happens!Like Disney land, just less...'cartooney'.
"""
def main():
    print("Workflow component v1.1.7: \n")
    print("Please be patient, this MAY take awhile...")
    (inputFile, outputFile) = parse_cmd_args()
    lines = readInput( inputFile )
    seorigin( outputFile, lines )

"""
The main function is run below.
"""
if __name__ == "__main__":
    main()
