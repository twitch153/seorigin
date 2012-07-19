#!/usr/bin/env python

import sys, getopt, re, os, sqlite3, types

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
        print("   Label classes are separate by seven classes: ")
        print("   type label, class label, string label, attribute label, ")
        print("   privilege label, argument label, and role label.\n")
        print("   When inserting labels into SEorigin's database we consider the label class as\n   an integer.\n")
        print("   Label integer types are as follows: ")
        print("   1 = Type label\n   2 = Attribute Label\n   3 = Classes label\n   4 = Privilege label")
        print("   5 = String/File label\n   6 = Argument label\n   7 = Role label\n")
def statementHelp():
        print("Statements: ")
        print("===========\n")
        print("   Statement classes: ")
        print("   ===================")
        print("   Statement classes are separate by four classes: ")
        print("   rule statements, interface statements, assign statements, and\n   declare statements.\n")
        print("   When searching for statements types throughout the parsed output we consider")
        print("   the statement class as an integer.\n")
        print("   Statement integer types are as follows: ")
        print("   0 = Rule statement\n   1 = Interface statement\n   2 = Assign statement\n   3 = Declare statement")

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
    defOutFile = os.path.join(os.environ["PWD"], 'seorigin.db') # Default output location.

    #Set up arguement flags for script execution.
    for o, p in opts:
        if o in ['-i', '--input']:
            inputFile=p
            inputCheck = False
        elif o in ['-o', '--output']:
            outputFile = sqlite3.connect(p)
            outputCheck=False
        elif o in ['-h', '--help']:
            print("\n")
            usage()
            print("\n")
            labelHelp()
            statementHelp()
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
    elif re.search('^{', line):
        pass
    elif re.search('\',`', line):
        pass
    # Checks for rule calls
    elif re.search('^allow', line):
        statementValue = 0
    elif re.search('^type_.*', line):
        statementValue = 0
    elif re.search('^dontaudit', line):
        statementValue = 0
    elif re.search('^auditallow', line):
        statementValue = 0
    elif re.search('^range_transition', line):
        statementValue = 0
    # Checks for interface calls
    elif re.search('^.*\(', line):
        statementValue = 1
    # Checks for assign calls
    elif re.search('^.*attribute', line):
        statementValue = 2
    elif re.search('^typealias', line):
        statementValue = 2
    elif re.search('^class', line):
        statementValue = 2
    # Checks for declaration calls
    elif re.search('type .*', line):
        statementValue = 3
    elif re.search('types .*', line):
        statementValue = 3
    elif re.search('role .*', line):
        statementValue = 3
    else:
        pass
        #print('Unknown line: ' + line)
    return statementValue

"""
getRuleType() goes through the lines of rules statements and returns the rule type.
"""
def getRuleType( ruleLine ):
    ruleType = 0
    if re.search('^allow', ruleLine):
        ruleType = 1
    elif re.search('^type_.*', ruleLine):
        ruleType = 2
    elif re.search('^dontaudit', ruleLine):
        ruleType = 3
    elif re.search('^auditallow', ruleLine):
        ruleType = 4
    elif re.search('^range_transition', ruleLine):
        ruleType = 5
    return ruleType

"""
getFileName() goes through a source record and returns the file name.
"""
def getFileName( record ):
    sourceFile = ''
    if re.search('^# \w+/.*$', record):
        record = re.sub('^# ', '', record)
        sourceFile = record
    return sourceFile

"""
getDefinitionName() goes through a definition record and returns the definition name.
"""
def getDefinitionName( record ):
    definitionName = ''
    if re.search('^# ', record):
        record = re.sub('^# ', '', record)
        definitionName = record
    return definitionName

"""
getSourceLine() detects the source line of a source record, parses it out using regular expressions, then returns it.
"""
def getSourceLine( record ):
    recordLine = ''
    sourceCheck = False
    if re.search('^## source.*$', record):
        sourceCheck = True
    elif re.search('^\w*.*$', record):
        sourceCheck = True
    elif re.search('^\n', record):
        sourceCheck = False
    if sourceCheck:
        record = re.sub('^## source.*$', '', record)
        record = re.sub('^# .*$', '', record)
    return record

"""
getLineNumber() goes through a source record and returns the line number.
"""
def getLineNumber( record ):
    lineNum = 0
    if re.search('^# line: ', record):
        record = re.sub('^# line: ', '', record)
        lineNum = record
    return lineNum

"""
parseForLabelSets() goes through the line given and parses out the proper label sets for the line.
"""
def parseForLabelSets( line ):
    try:
        labels = ''
        labelSet = re.sub('^if.*$', '', line)
        labelSet = re.sub('^.*\(', '', labelSet)
        labelSet = re.sub('^}.*$', '', labelSet)
        labelSet = re.sub('\)', '', labelSet)
        labelSet = re.sub(',', '%', labelSet)
        labelSet = re.sub('{.*%}', ',', labelSet)
        labelSet = re.sub('\n', '', labelSet)
        labelSet = labelSet.split("%")
        for labels in labelSet:
            labels = re.sub('^\w*', '', labels)
            labels = re.sub('^ \w*', '', labels)
            if re.search('\~{', labels):
                if re.search('} \~{', labels):
                    labels = re.sub('^\$\d+', '', labels)
                    labels = re.sub('\$\d+:\w+ ', '', labels)
                    labels = re.sub('~{', '@~{', labels)
                else:
                    labels = re.sub('^\$\d+.*~{', '@~{', labels)
                    labels = re.sub('.*~{', '@~{', labels)
            else:
                if re.search('} {', labels):
                    labels = re.sub('^\$\d+', '', labels)
                    labels = re.sub('\$\d+:\w+ ', '', labels)
                    labels = re.sub('{', '@{', labels)
                else:
                    labels = re.sub('^\$\d+.*{', '@{', labels)
                    labels = re.sub('.*{', '@{', labels)
            if re.search('.*} ~{.*$', labels):
                labels = re.sub('} ~{', '}@~{', labels)
            elif re.search('.*} {.*$', labels):
                labels = re.sub('} {', '}@{', labels)
            labels = re.sub('};', '}', labels)
            labels = re.sub('\n', '', labels)
            labels = re.sub('^ $', '', labels)
            labels = re.sub('^ ', '', labels)
            labels = labels.split('@')
            
            return labels
    except Exception as err:
        print("\nparseForLabelSets Error {0}".format(err),"\n")

"""
getSourceFromRule() goes through a rule statement such as this:

    "allow $1 $2:file { mmap_file_perms ioctl lock };"

and would return the source labels which in this case would be: $1.
"""
def getSourceFromRule( line ):
    try:
        setCheck = False
        line = re.sub(':.*$', '', line)
        source = re.sub('^\w+[_\w+] ', '', line)
        if re.search('^{', source):
            setCheck = True
        elif re.search('}', source):
            setCheck = False
        if setCheck:        
            source = re.sub('}.*$', '}', source)
        else:
            source = re.sub(' .*$', '', source)
        return source
    except Exception as err:
        print('\ngetSourceFromRule() Error{0}'.format(err),'\n')
        usage()

"""
getDestinationFromRule() goes through a rule statement such as this:

    "allow $1 $2:file { mmap_file_perms ioctl lock };"

and would return the destination label which in this case would be: $2.
"""
def getDestinationFromRule( line ):
    destination = ''
    setCheck = False
    line = re.sub(':.*$', '', line)
    if re.search('{', line):
        setCheck = True
    elif re.search('}', line):
        setCheck = False
    if setCheck:
        destination = re.sub('^\w+[_\w+] ', '', line)
        if re.search('^\$\d+', destination):
            destination = re.sub('^\$\d+ ', '', destination)
        elif re.search('^\w+', destination):
            destination = re.sub('^\w+ ', '', destination)
        elif re.search('^[~{].*} ', destination):
            destination = re.sub('^[~{].*} ', '', destination)
    else:
        destination = re.sub('^\w+[_\w+] ', '', line)
        if re.search('^\$\d+', destination):
            destination = re.sub('^\$\d+ ', '', destination)
        elif re.search('^\w+', destination):
            destination = re.sub('^\w+ ', '', destination)
        elif re.search('^[~{].*} ', destination):
            destination = re.sub('^[~{].*} ', '', destination)
    return destination

"""
getClassFromRule() goes through a rule statement such as this:

    "allow $1 $2:file { mmap_file_perms ioctl lock };"

and would return the destination label which in this case would be: file.
"""
def getClassesFromRule( line ):
    classes = ''
    setCheck = False
    line = re.sub('^.*:', '', line)
    line = re.sub(';', '', line)
    if re.search('^{', line):
        setCheck = True
    elif re.search('}', line):
        setCheck = False
    if setCheck:
        classes = re.sub('}.*$', '}', line)
    else:
        classes = re.sub(' .*$', '', line)
    return classes

"""
getPrivilegesFromRule() goes through a rule statement such as this:

    "allow $1 $2:file { mmap_file_perms ioctl lock };"

and would return the destination label which in this case would be: 
the label set { mmap_file_perms ioctl lock }.
"""
def getPrivilegesFromRule( line ):
    try:
        permissions = ''
        setCheck = False
        line = re.sub('^.*:', '', line)
        line = re.sub(';', '', line)
        if re.search('^{.*}', line):
            permissions = re.sub('^{.*} ', '', line)
        elif re.search('^\w+ ', line):
            permissions = re.sub('^\w+ ', '', line)
        elif re.search('^\$\d+ ', line):
            permissions = re.sub('^\$\d+ ', '', line)
        return permissions
    except Exception as err:
        print("\ngetPrivilegesFromRule() Error{0}".format(err),"\n")
        usage()
"""
labelsToList( line ) gets the labels from a specific line and returns the labels parsed out from the line as a list of
the labels of that line.
"""
def labelsToList( line ):
    try:
        labels = ''
        statementCheck = False
        interfaceCheck = False
        labelSetCheck = False
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
        if re.search('.*{', line):
            labelSetCheck = True
        elif re.search('}', line):
            labelSetCheck = False
        if re.search('^.*\(', line):
            interfaceCheck = True

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
            labels = labels.split()

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

        if labelSetCheck:
            labels = parseForLabelSets(line)
        return labels
    except Exception as err:
        print("\nlabelsToList() Error: {0}".format(err),"\n")

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
        (FileId Integer primary key AUTOINCREMENT, Filename text)''')

        database.execute('''create table if not exists tb_files
        (FileId Integer primary key AUTOINCREMENT, Filename text)''')

        database.execute('''create table if not exists tb_definitionNames 
        (definitionId Integer primary key AUTOINCREMENT NOT NULL, DefinitionName 
        Text NOT NULL)''')

        database.execute('''create table if not exists tb_label
        (LabelId Integer PRIMARY KEY AUTOINCREMENT NOT NULL, LabelClass INTEGER NOT NULL, 
        Name Text NOT NULL)''')

        database.execute('''create table if not exists tb_labelSet
        (LabelSetId Integer NOT NULL, LabelId NOT NULL, Modifier Integer NOT NULL, 
        primary key(LabelSetID, LabelId), foreign key(LabelId) references tb_label(LabelId))''')

        database.execute('''create table if not exists tb_statement_declare 
        (StatementId Integer primary key AUTOINCREMENT NOT NULL, DeclarationClass Integer NOT NULL, 
        TargetId Integer NOT NULL, AliasId Integer, foreign key(TargetId) references tb_labelSet(LabelSetId), 
        foreign key(AliasId) references tb_LabelSet(LabelSetId))''')

        database.execute('''create table if not exists tb_statement_rule
        (StatementId INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, RuleClass Integer NOT NULL,
        SourceId INTEGER NOT NULL, TargetId INTEGER NOT NULL, ClassesId INTEGER NOT NULL, 
        PrivilegeId INTEGER NOT NULL, FOREIGN KEY(SourceId) REFERENCES TB_LABELSET(LabelSetId), 
        FOREIGN KEY(TargetId) REFERENCES TB_LABELSET(LabelSetId), FOREIGN KEY(ClassesId) 
        REFERENCES TB_LABELSET(LabelSetId), FOREIGN KEY(PrivilegeId) 
        REFERENCES TB_LABELSET(LabelSetId))''')

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
                #line = re.sub('^# ', '', line)
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
            #line = re.sub('# line: ', '', line)# Removes "# line: " from input.
            if re.search('^## source', line):
                sourceCheck = True
            elif re.search('^\n', line):
                sourceCheck = False
            if sourceCheck:
                #line = re.sub('^# ', '', line)
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
def insertFile( outputFile, sourceFile ):
    try:
        fileId = 0
        database = outputFile.cursor()
        if sourceFile == '':
            pass
        else:
            File = (sourceFile, )
            database.execute('''select * from tb_files where Filename = ?''', File)
            postPopCheck = database.fetchone()
            if postPopCheck == None:    
                database.execute('''insert into tb_files values (NULL, ?)''', File)
            else:
                database.execute('''select fileId from tb_files where Filename = ?''', File)
                fileId = database.fetchone()
        return fileId
    except Exception as err:
        print("\ninsertFile() Error: {0}".format(err),"\n")
        usage()
    outputFile.commit()
    database.close()

"""
insertDefinitionNames() writes specific information from the input file to tb_definitionNames in the seorigin db.
"""
def insertDefinitionName( outputFile, definitionCall ):
    try:
        database = outputFile.cursor()
        definitionId = 0
        if definitionCall == '':
            pass
        else:
            defName = (definitionCall, )
            database.execute('''select * from tb_definitionNames where DefinitionName = ?''', defName)
            postPopCheck = database.fetchone()
            if postPopCheck == None:
                database.execute('''insert into tb_definitionNames values (NULL,?)''', defName)
            else:
                database.execute('''select definitionId from tb_definitionNames 
                where DefinitionName = ?''', defName)
                definitionId = database.fetchone()
        return definitionId
    except Exception as err:
        print("\ninsertDefinitionNames() Error: {0}".format(err),"\n")
        usage()
    outputFile.commit()
    database.close()

"""
insertLabel() writes specific information from the input file to tb_label in the seorigin db.
"""
def insertLabel( outputFile, label, classList, permsList ):
    try:
        database = outputFile.cursor()
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
        database.execute('''select labelId from tb_label where Name = ?''', labelCheck)
        labelId = database.fetchone()
        return labelId
    except Exception as err:
        print("\ninsertLabel() Error: {0}".format(err),"\n")
        usage()
    outputFile.commit()
    database.close()

"""
prepLabelset() is used to prepare tb_labelSet for population of tb_labelSet if no
values are found inside the table.
"""
def prepLabelSet( outputFile, labelId, modifier ):
    try:
        database = outputFile.cursor()
        labelSetId = 1
        labelId = int(''.join(map(str,labelId)))
        values = (labelSetId, labelId, modifier)
        database.execute('''insert into tb_labelSet values (?, ?, ?)''', values)
    except Exception as err:
        print("\nprepLabelSet Error{0}".format(err),"\n")
    outputFile.commit()
    database.close()

"""
insertLabelSet() writes label set values to tb_labelSet based on the label set which can be one label:
'foo_t' or a label set such as: '{ foo_t bar_t }' in this case the label set would have one label set
id to match the label set which would include the labelIds of the labels inside.
"""
def insertLabelSet( outputFile, labelSet, classList, permsList ):
    try:
        database = outputFile.cursor()
        modifier = 1
        labelSetId = 0
        labelId = 0
        if not re.search('\~', labelSet):
            modifier = 0

        if not re.search('{', labelSet):
            label = labelSet
            if label == '~':
                pass
            else:
                labelId = insertLabel(outputFile, label, classList, permsList)
                database.execute('''select * from tb_labelSet''')
                popCheck = database.fetchone()
                if popCheck == None:
                    prepLabelSet( outputFile, labelId, modifier )
                else:
                    database.execute('''select labelSetId from tb_labelSet where labelId = ?''', labelId)
                    labelSetId = database.fetchone()
                    if labelSetId == None:
                        labelId = int(''.join(map(str,labelId)))
                        database.execute('''select max(labelSetId)+1 from tb_labelSet''')
                        labelSetId = database.fetchone()
                        labelSetId = int(''.join(map(str,labelSetId)))
                        values = (labelSetId, labelId, modifier)
                        try:
                            database.execute('''insert into tb_labelSet values (?, ?, ?)''', values)
                        except sqlite3.IntegrityError:
                            pass
        else:
            database.execute('''select * from tb_labelSet''')
            popCheck = database.fetchone()
            if popCheck == None:
                prepLabelSet( labelId, modifier )
            labelSet = re.sub('[{}]', '', labelSet)
            labelSet = re.sub('\~', '', labelSet)
            labelSet = re.sub('^ ', '', labelSet)
            labelSet = labelSet.split()
            for label in labelSet:
                labelId = insertLabel(outputFile, label, classList, permsList)
                database.execute('''select labelSetId from tb_labelSet where labelId = ?''', labelId)
                labelSetId = database.fetchone()
                if labelSetId == None:
                    database.execute('''select max(labelSetId)+1 from tb_labelSet''')
                    labelSetId = database.fetchone()
                labelId = int(''.join(map(str,labelId))) # converts Tuple to int
                labelSetId = int(''.join(map(str,labelSetId)))
                values = (labelSetId, labelId, modifier)
                try:
                    database.execute('''insert into tb_labelSet values (?, ?, ?)''', values)
                except sqlite3.IntegrityError:
                    pass
        if type(labelId) is not tuple:
            labelId = (labelId, ) # This is necessary to have unless we want to run
                                  # into "parameter not supported" errors.
        database.execute('''select labelSetId from tb_labelSet where labelId = ?''', labelId)
        labelSetId = database.fetchone()    
        return labelSetId
    except Exception as err:
        print("\ninsertLabelSet() Error: {0}".format(err),"\n")
        usage()
    outputFile.commit()
    database.close()

"""
insertAllLabels() goes through the list of labels given to it then inserts it into the seorigin db.
"""
def insertAllLabels( outputFile, line, classList, permsList ):
    try:
        selfCheck = ''
        labels = labelsToList( line )
        for label in labels:
            if label == '':
                pass
            else:
                insertLabelSet( outputFile, label, classList, permsList )
    except Exception as err:
        print("\ninsertAllLabels() Error: {0}".format(err),"\n")
        usage()
    outputFile.commit()
    database.close()

def insertStatementRule( outputFile, line, classList, permsList ):
    try:
        print(line)
        setCheck = False
        database = outputFile.cursor()
        sourceLabel = getSourceFromRule(line)
        destinationLabel = getDestinationFromRule(line)
        classesLabel = getClassesFromRule(line)
        privilegesLabel = getPrivilegesFromRule(line)
        ruleType = getRuleType(line)
        if re.search("^.*self.*$", destinationLabel):
            destinationLabel = re.sub('self', sourceLabel, destinationLabel)
        srcLabelSetId = int(''.join(map(str, insertLabelSet( outputFile, sourceLabel, classList, permsList ))))
        dstLabelSetId = int(''.join(map(str, insertLabelSet( outputFile, destinationLabel, classList, permsList ))))
        classLabelSetId = int(''.join(map(str, insertLabelSet( outputFile, classesLabel, classList, permsList ))))
        prvsLabelSetId = int(''.join(map(str, insertLabelSet( outputFile, privilegesLabel, classList, permsList ))))
        rule = (ruleType, srcLabelSetId, dstLabelSetId, classLabelSetId, prvsLabelSetId)
        Ids = (srcLabelSetId, dstLabelSetId, classLabelSetId, prvsLabelSetId)
        database.execute('''select statementId from tb_statement_rule where sourceId = ? 
        and targetId = ? and classesId = ? and privilegeId = ?''', Ids)
        statementId = database.fetchone()
        if statementId == None:
            database.execute('''insert into tb_statement_rule values (NULL, ?, ?, ?, ?, ?)''', rule)
        else:
            pass
        database.execute('''select statementId from tb_statement_rule where sourceId = ? 
        and targetId = ? and classesId = ? and privilegeId = ?''', Ids)
        statementId = database.fetchone()

        return statementId
    except Exception as err:
        print("\ninsertStatementRule() Error: {0}".format(err),"\n")
        usage()
    outputFile.commit()
    database.close()

def insertStatementAssign( outputFile, line, classList, permsList ):
    try:
        database = outputFile.cursor()
        labels = labelsToList( line )
        for label in labels:
            if label == '':
                pass
            else:
                insertLabelSet( outputFile, label, classList, permsList )
        #database.execute('''insert into tb_statement_assign values (NULL, ?, ?, NULL, NULL, NULL)''', source)
        pass
    except Exception as err:
        print("\ninsertStatementAssign() Error: {0}".format(err),"\n")
        usage()
    outputFile.commit()
    database.close()

def insertStatementInterface( outputFile, line, classList, permsList ):
    try:
        database = outputFile.cursor()
        labels = labelsToList( line )
        for label in labels:
            if label == '':
                pass
            else:
                insertLabelSet( outputFile, label, classList, permsList )
        #database.execute('''insert into tb_statement_interface values (NULL, ?, ?, NULL, NULL, NULL)''', source)
        pass
    except Exception as err:
        print("\ninsertStatementInterface() Error: {0}".format(err),"\n")
        usage()
    outputFile.commit()
    database.close()

def insertStatementDeclare( outputFile, line, classList, permsList ):
    try:
        database = outputFile.cursor()
        labels = labelsToList( line )
        for label in labels:
            if label == '':
                pass
            else:
               insertLabelSet( outputFile, label, classList, permsList )
        #database.execute('''insert into tb_statement_declare values (NULL, ?, ?, ?)''', source)
        #database.execute('''select StatementId from tb_statement''')
        #return StatementId
    except Exception as err:
        print("\ninsertStatementDeclare() Error: {0}".format(err),"\n")
        usage()
    outputFile.commit()
    database.close()

"""
writeOut( outputFile, output) writes output to the file we want to have it outputted to. This will be included
for debugging purposes.
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
insertSource() calls all necessary commands required to populate tables with source 
record information.
"""
def insertSource( outputFile, record, classList, permsList ):
    try:
        database = outputFile.cursor()
        fileName = getFileName( record )
        fileId = insertFile( outputFile, fileName )
        recordLine = getSourceLine( record ) 
        statementType = getStatementType(recordLine)
        lineNum = getLineNumber( record )
        # If we find a rule statement
        if statementType == 0:
            statementId = int(''.join(map(str, insertStatementRule( outputFile, record, classList, permsList ))))
            source = ( fileId, lineNum, statementId )
            database.execute('''insert into tb_source values (?, ?, NULL, ?, NULL, NULL)''', source)
        # If we find an interface statement
        elif statementType == 1:
            statementId = insertStatementInterface( outputFile, record, classList, permsList )
            source = ( fileId, lineNum, statementId )
            #database.execute('''insert into tb_source values (?, ?, NULL, NULL, ?, NULL)''', source)
        # If we find an assignation statement
        elif statementType == 2:
            statementId = insertStatementAssign( outputFile, record, classList, permsList )
            source = ( fileId, lineNum, statementId )
            #database.execute('''insert into tb_source values (?, ?, NULL, NULL, NULL, ?)''', source)
        # If we find declaration statement
        elif statementType == 3:
            statementId = insertStatementDeclare( outputFile, record, classList, permsList )
            source = ( fileId, lineNum, statementId )
            #database.execute('''insert into tb_source values (?, ?, ?, NULL, NULL, NULL)''', source)
    except Exception as err:
        print("insertSource() Error: {0}".format(err),"\n")
        usage()

"""
cleanDefinition() cleans up existing records by looking in tb_definitionName for the existing definition
and Id of a definition name, then looks in tb_definition_content for all records for that Id. If it finds
that content exists then it deletes all the information corressponding to that definitionId.
"""
def cleanDefinition( outputFile, definitionName ):
    try:
        database = outputFile.cursor()
        definitionName = (definitionName, )
        database.execute('''select definitionId from tb_definitionNames where definitionName = ?''', definitionName)
        definitionId = database.fetchone()
        database.execute('''select * from tb_definition_content where DefinitionId = ?''', definitionId)
        definitionContent = database.fetchone() 
        if not definitionContent == None:
            database.execute('''delete tb_definition_content where DefinitionId = ?''', definitionId)
    except Exception:
        pass

"""
insertDefinition() takes in the definition record, disects it for information pertaining to 
"""
def insertDefinition( outputFile, record, classList, permsList ):
    try:
        database = outputFile.cursor()
        defName = getDefinitionName( record )
        if not defName == '':
            cleanDefinition( outputFile, defName )
        definitionId = insertDefinitionName(outputFile, defName)
        LineType = getStatementType(record)
        if LineType == 0:
            statementId = int(''.join(map(str, insertStatementRule( outputFile, record, classList, permsList ))))
            content = (definitionId, statementId, )
            database.execute('''insert into tb_definition_content values 
            (?, NULL, ?, NULL, NULL)''', content)
        elif LineType == 1:
            statementId = insertStatementInterface( outputFile, record, classList, permsList )
            #content = (definitionId, statementId, )
            #database.execute('''insert into tb_definition_content values
            #(?, NULL, NULL, ?, NULL)''', content)
        elif LineType == 2:
            statememtId = insertStatementAssign( outputFile, record, classList, permsList )
            #content = (definitionId, statementId, )
            #database.execute('''insert into tb_definition_content values
            #(?, NULL, NULL, NULL, ?)''', content)
        elif LineType == 3:
            statementId = insertStatementDeclare( outputFile, record, classList, permsList )
            #content = (definitionId, statementId, )
            #database.execute('''insert into tb_definition_content values
            #(?, ?, NULL, NULL, NULL)''', content)
    except Exception as err:
        print("insertDefinition() Error: {0}".format(err),"\n") 
    outputFile.commit()
    database.close()
"""
seorigin( outputFile, lines ) creates the seorigin database by calling the necessary functions to 
create and write the seorigin database.
"""
def seorigin( outputFile, lines ):
    try:
        classList = getClassList()
        permsList = getPermsList()
        createTables( outputFile )
        source_record = cleanSource( lines )
        definition_record = cleanDefine( lines )

        for definition in definition_record:
            insertDefinition( outputFile, definition, classList, permsList )
        for source in source_record:
            insertSource( outputFile, source, classList, permsList )

    except Exception as err:
        print("seorigin() Error: {0}".format(err),"\n")
        usage()

"""
main() is where all the magic happens! Like Disney land, just less...'cartooney'.
"""
def main():
    print("Workflow component v1.1.9: \n")
    print("Please be patient, this MAY take awhile...")
    (inputFile, outputFile) = parse_cmd_args()
    lines = readInput( inputFile )
    seorigin( outputFile, lines )

"""
The main function is run below.
"""
if __name__ == "__main__":
    main()
