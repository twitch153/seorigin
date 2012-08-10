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
        print(" Labels: ")
        print(" =======\n")
        print("   Label classes: ")
        print("   ============== ")
        print("   Label classes are separate by seven classes: ")
        print("   type label, class label, string label, attribute label, ")
        print("   privilege label, argument label, and role label.\n")
        print("   When inserting labels into SEorigin's database we consider the label class as\n   an integer.\n")
        print("   Label integer types are as follows: ")
        print("   1 = Type label\n   2 = Attribute Label\n   3 = Classes label\n   4 = Privilege label")
        print("   5 = String/File label\n   6 = Argument label\n   7 = Role label\n")
        print("\n Label Sets: ")
        print(" ===========\n")
        print("   Label Set Ids: ")
        print("   ==============")
        print("   Label set Ids are dynamically generated identification numbers")
        print("   for label sets.")
        print("   A label set can be considered as one label when going into the\n   \"insertLabelSet()\" function such as:\n\tfoo_t")
        print("   it can also be considered a set of labels such as:\n\t{ foo_t bar_t }")
        print("   Label Set Ids are generated in this fashion:\n")
        print("   foo_t\n")
        print("      labelId = 1")
        print("      labelSetId = 1\n")
        print("   { foo_t bar_t }\n")
        print("      labelId = 1 (for foo_t)")
        print("      labelSetId = 2")
        print("      labelId = 2 (for bar_t)")
        print("      labelSetId = 2\n")    
def statementHelp():
        print(" Statements: ")
        print(" ===========\n")
        print("   Statement classes: ")
        print("   ===================")
        print("   Statement classes are separate by four classes: ")
        print("   rule statements, interface statements, assign statements, and\n   declare statements.\n")
        print("   When searching for statements types throughout the parsed output we consider")
        print("   the statement class as an integer.\n")
        print("   Statement integer types are as follows: ")
        print("   0 = Rule statement\n   1 = Interface statement\n   2 = Assign statement\n   3 = Declare statement")
        print("\n Rule Statements: ")
        print(" ================\n")
        print("   Rule classes: ")
        print("   ============= ")
        print("   Rule classes are separate by five classes: ")
        print("   allow statements, type statements, dontaudit statements,\n   auditallow statements and range_transition statements.\n")
        print("   when inserting rule types into SEOrigin's database we consider")
        print("   the rule class as an integer for simplicity.\n")
        print("   Rule integer types are as follows: ")
        print("   1 = Allow statements\n   2 = Type statements\n   3 = Dontaudit statements\n   4 = Auditallow statements")
        print("   5 = Range_transition statements.\n")

#TODO find range in range_transition statements such as:
# range_transition $1 initrc_exec_t:process s0 - mls_systemhigh
# understand what they mean and how to handle them.

"""
parse_cmd_agrs() sets up the -i -o and -h flags for the policy-parser script. See usage for what each flag is.
"""
def parse_cmd_args():
    shortOpts = 'i:o:h'
    longOpts = ['input=','output=','help']

    opts, extraparams = getopt.getopt(sys.argv[1:], shortOpts, longOpts)

    inputCheck = False   # Boolean check to see if input location has been set.
    outputCheck = False   # Boolean check to see if output location has been set.

    #Set up arguement flags for script execution.
    for o, p in opts:
        if o in ['-i', '--input']:
            if os.path.exists(p):
                inputFile=p
                if not os.access(p, os.R_OK):
                    print("\nFile %s does not have read permissions!\nPlease specify new input file or resort to default.\n" % p)
                    sys.exit()
            else:
                print("\nFile %s does not exist!\nPlease specify new input file.\n" % p)
                sys.exit()
            inputCheck = True
        elif o in ['-o', '--output']:
            try:
                outputFile = sqlite3.connect(p)
            except sqlite3.OperationalError as err:
                print("\nCritical error: {0}".format(err))
                print("\nSuggestions:\n\n   *Try new output file location.\n   *Check permissions of database.\n   *Gently weep.\n")
                sys.exit()
            outputCheck=True
        elif o in ['-h', '--help']:
            print("\n")
            usage()
            print("\n")
            labelHelp()
            statementHelp()
            sys.exit()

# Sanity check to make sure the parsed information is getting written to some location.
    if not inputCheck and outputCheck:
        print("\nInput file not specified, please specify input file to continue.")
        sys.exit()
    if not outputCheck and inputCheck:
        print ("\nOutput file not specified, please specify new output file to continue.")
        sys.exit()
    if not outputCheck and not inputCheck:
        print("\nInput file and output file are not specified.\n\nPlease specify both files in order to continue.")
        sys.exit()
    return( inputFile, outputFile )
	
"""
readInput( inputFile (File) ) reads in the specified file. If a file does not exist it will shoot an exception.
"""
def readInput( inputFile ):
    try:
        f=open(inputFile, 'r') # This creates the function for opening the file, and assigns it to f.
    except Exception as err:
        print("\nreadInput() Error: {0}".format(err),"\n")

    fileLines = f.readlines()
    f.close()

    return fileLines

"""
getStatementType( line (String) ) read through a line of the input and searches for each statement type and assigns
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
    elif re.search('\',`', line):
        pass
    elif line == '':
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
    elif re.search('^neverallow', line):
        statementValue = 0
    elif re.search('^range_transition', line):
        statementValue = 0
    elif re.search('^type_member', line):
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
    elif re.search('^role.*types', line):
        statementValue = 2
    elif re.search('^type.*,.*', line):
        statementValue = 2
    # Checks for declaration calls
    elif re.search('^type', line):
        statementValue = 3
    elif re.search('^role', line):
        statementValue = 3
    elif re.search('^attribute', line):
        statementValue = 3
    elif re.search('^\{', line):
        statementValue = 3
    else:
        print('Unknown line: ' + line)
        pass
    return statementValue

"""
getDeclareFromType( declareLine (String) ) goes through the lines of declaration statements and returns the declare type
of the declaration line as int.
"""
def getDeclareType( declareLine ):
    try:
        declareType = 0
        if re.search('^type', declareLine):
            declareType = 1
        elif re.search('^role', declareLine):
            declareType = 2
        elif re.search('^attribute', declareLine):
            declareType = 3
        elif re.search('^{', declareLine):
            declareType = 4
        return declareType
    except Exception as err:
        print("getDeclareType Error: {0}".format(err),"\n")

"""
getRuleType( ruleLine (String) ) goes through the lines of rules statements and returns the rule type as an int.
"""
def getRuleType( ruleLine ):
    ruleType = 0
    if re.search('^allow', ruleLine):
        ruleType = 1
    elif re.search('^type_transition', ruleLine):
        ruleType = 2
    elif re.search('^dontaudit', ruleLine):
        ruleType = 3
    elif re.search('^auditallow', ruleLine):
        ruleType = 4
    elif re.search('^range_transition', ruleLine):
        ruleType = 5
    elif re.search('^neverallow', ruleLine):
        ruleType = 6
    elif re.search('^type_member', ruleLine):
        ruleType = 7
    elif re.search('^type_change', ruleLine):
        ruleType = 8
    return ruleType

"""
getFileName( record (String) ) goes through a source record and returns the file name.
"""
def getFileName( record ):
    sourceFile = ''
    if re.search('^# \w+/.*$', record):
        record = re.sub('^# ', '', record)
        sourceFile = record
    return sourceFile

"""
getDefinitionName( record (String) ) goes through a definition record and returns the definition name.
"""
def getDefinitionName( record ):
    definitionName = ''
    if re.search('^# ', record):
        record = re.sub('^# ', '', record)
        definitionName = record
    return definitionName

"""
getSourceLine( record (String) ) detects the source line of a source record, parses it out using regular expressions,
then returns it.
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
getLineNumber( record (String) ) goes through a source record and returns the line number.
"""
def getLineNumber( record ):
    lineNum = 0
    if re.search('^# line: ', record):
        record = re.sub('^# line: ', '', record)
        lineNum = record
    elif re.search('^# Line: ', record):
        record = re.sub('^# Line: ', '', record)
        lineNum = record
    elif re.search('# \w+/.*\.te:\d+', record):
        print('\nOlder parsed file format detected in source record line: \n' + record,'\n')
        print('Please use a new input file with the updated parsed format.')
        sys.exit()
    return lineNum

"""
getSourceFromRule( line (String) ) goes through a rule statement such as this:

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

"""
getDestinationFromRule( line (String) ) goes through a rule statement such as this:

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
getClassFromRule( line (String) ) goes through a rule statement such as this:

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
getPrivilegesFromRule( line (String) ) goes through a rule statement such as this:

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

"""
getInterfaceArgs( line (String) ) reads in the line of an interface statement and returns in interface
arguments as a list. 
If we get an interface statement such as:
    domain_entry_file($1,$2)
We would return the arguments in as list like: ['$1', '$2']
"""
def getInterfaceArgs( line ):
    try:
        line = re.sub('^.*\(', '(', line)
        args = re.sub('[\(\)]', '', line)
        if re.search('^\w+[_\w+]$', args):
            args = args.split()
        elif re.search('^\$\d+$', args):
            args = args.split()
        else:
            args = args.split(',')
        return args
    except Exception as err:
        print('\ngetInterfaceArgs() Error: {0}'.format(err),"\n")

'''
getInterfaceName( interfaceLine (String) ) grabs the name of the interface statement and returns the name as a string
'''
def getInterfaceName( interfaceLine ):
    try:
        name = ''
        name = re.sub('\(.*\)', '', interfaceLine)
        return name
    except Exception as err:
        print('\ngetInterfaceName() Error: {0}'.format(err),'\n')

'''
getTargetFromAssignation( line (String) ) takes in an assignation line such as:
    role system_r types $1;
        or
    typeattribute file domain, foo_t, bar_t;
and returns the target label in the first case it would be: system_r
in the second case it would be: file
'''
def getTargetFromAssignation( line ):
    try:
        target = ''
        line = re.sub('^\w+ ', '', line)
        target = re.sub(' .*;', '', line)
        return target
    except Exception as err:
        print('\ngetTargetFromAssignation() Error: {0}'.format(err),"\n")

'''
getAssignedFromAssignation( line (String) ) takes in an assignation line such as:
    role system_r types $1;
        or
    typeattribute file domain, foo_t, bar_t;
and returns the assigned labels in the first case it would simply be: $1
but if more than one assigned label is found they would be returned as a label set
in this case it would be: { domain foo_t bar_t }
'''
def getAssignedFromAssignation( line ):
    try:
        assigned = ''
        assigned = re.sub('^\w+ ', '', line)
        if re.search('^\w+[_\w+]', assigned):
            assigned = re.sub('^\w+[_\w+] ', '', assigned)
        elif re.search('^\$\d+', assigned):
            assigned = re.sub('^\$\d+ ', '', assigned)
        assigned = re.sub('^types ', '', assigned)
        if re.search('^.*, .*', assigned):
            assigned = re.sub(',', '', assigned)
            assigned = re.sub('^', '{ ', assigned)
            assigned = re.sub(';', ' }', assigned)
        else:
            assigned = re.sub(';', '', assigned)
        return assigned
    except Exception as err:
        print('\ngetAssignedFromAssignation() Error: {0}'.format(err),"\n")

'''
getTargetFromDeclare( declareLine (String) ) takes in a declaration line such as:
    role system_r
and returns the target of the declaration, which would be: system_r
'''
def getTargetFromDeclare( declareLine ):
    try:
        target = ''
        target = re.sub('^\w+[_\w+] ', '', declareLine)
        target = re.sub(' alias .*$', '', target)
        target = re.sub(';', '', target)
        return target 
    except Exception as err:
        print("\ngetTargetFromDeclare() Error: {0}".format(err),"\n")
        print("While parsing target from line: %s.\n" % declareLine)

'''
getAliasFromDeclare( declareLine (String) ) takes in a declaration line like this: 
    role system_r alias $1
and returns the alias, which would be: $1
'''
def getAliasFromDeclare( declareLine ):
    try:
        alias = ''
        alias = re.sub('^.* alias ', '', declareLine)
        alias = re.sub(';', '', alias)
        return alias
    except Exception as err:
        print('\ngetAliasFromDeclare() Error: {0}'.format(err), '\n')
        print("While parsing alias from line: %s.\n" % declareLine)

'''
getAssignationType( assignLine (String) ) takes in a statement assign line from the input and returns the type
of assign statement it is in a numerical value.
'''
def getAssignationType( assignLine ):
    try:
        assignType = 0
        if re.search('^typeattribute', assignLine):
            assignType = 1
        elif re.search('^roleattribute', assignLine):
            assignType = 2
        elif re.search('^typealias', assignLine):
            assignType = 3
        elif re.search('^class', assignLine):
            assignType = 4
        elif re.search('^role', assignLine):
            assignType = 5
        elif re.search('^type', assignLine):
            assignType = 6
        return assignType
    except Exception as err:
        print('\ngetAssignationType() Error: {0}'.format(err),"\n")
        print("While getting assignment type from: %s.\n" % assignLine)

"""
getClassList() grabs the information from "SELinux Class list" and returns it as a list.
"""
def getClassList():
    try:
        classList = readInput(os.path.join(os.environ["PWD"], 'SELinux_Class_list.txt'))
        result = ['']
        for List in classList:
            List = re.sub('\n', '', List)
            result.append(List)
        return result
    except Exception as err:
        print("\ngetClassList() Error: {0}".format(err),"\n")

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

'''
Globaly declares classList for later use in the script.
'''
try:
    classList = getClassList()
except Exception as err:
    print("Error declaring global variable classList: {0}".format(err),"\n")
    sys.exit()

'''
Globaly declares permsList for later use in the script.
'''
try:
    permsList = getPermsList()
except Exception as err:
    print("Error declaring global variable permsList: {0}".format(err),"\n")
    sys.exit()

"""
getLabelClass( label(File), classList (File), permList(File) ) read through the labels of the input and searches for each statement type and assigns
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
createTables( outputFile (sqlite3 database) ) creates the necessary tables for the SQLite3 database
"""
def createTables( outputFile ):
    try:
        database = outputFile.cursor()
        database.execute('''Pragma foreign_keys=off''')

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
        foreign key(AliasId) references tb_labelSet(LabelSetId))''')

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

        database.execute('''create table if not exists tb_statement_assign
        (StatementId INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, AssignationType INTEGER NOT NULL,
        TargetLabelId INTEGER NOT NULL, AssignedLabelId INTEGER NOT NULL, FOREIGN KEY(TargetLabelId)
        REFERENCES TB_LABELSET(LabelSetId), FOREIGN KEY(AssignedLabelId) REFERENCES TB_LABELSET(LabelSetId))''')

        database.execute('''create table if not exists tb_definition_content
        (DefinitionId INTEGER NOT NULL, StatementDeclareId INTEGER, StatementRuleId INTEGER,
        StatementInterfaceId INTEGER, StatementAssignId INTEGER, FOREIGN KEY(DefinitionId)
        REFERENCES TB_DEFINITIONNAMES(DefinitionId), FOREIGN KEY(StatementDeclareId)
        REFERENCES TB_STATEMENT_DECLARE(StatementId), FOREIGN KEY(StatementRuleId)
        REFERENCES TB_STATEMENT_RULE(StatementId), FOREIGN KEY(StatementInterfaceId)
        REFERENCES TB_STATEMENT_INTERFACE(StatementId), FOREIGN KEY(StatementAssignId)
        REFERENCES TB_STATEMENT_ASSIGN(StatementId))''')

        database.execute('''create table if not exists tb_source
        (FileId INTEGER NOT NULL, LineNumber INTEGER NOT NULL, StatementDeclareId INTEGER,
        StatementRuleId INTEGER, StatementInterfaceId INTEGER, StatementAssignId INTEGER,
        FOREIGN KEY(StatementDeclareId) REFERENCES TB_STATEMENT_DECLARE(StatementId), 
        FOREIGN KEY(StatementRuleId) REFERENCES TB_STATEMENT_RULE(StatementId), 
        FOREIGN KEY(StatementInterfaceId) REFERENCES TB_STATEMENT_INTERFACE(StatementId),
        FOREIGN KEY(StatementAssignId) REFERENCES TB_STATEMENT_ASSIGN(StatementId))''')

    except sqlite3.OperationalError as err:
        print("\ncreateTables() Error: {0}".format(err),"\n")
        sys.exit()

    except Exception as err:
        print("\ncreateTables() Error: {0}".format(err),"\n")
    outputFile.commit()
    database.close()

"""
cleanDefine( lines (String) ) reads in lines of the input files and "cleans" them up, removing any unnecessary new lines for
the definition records and returns them in a clean array.
"""
def cleanDefine( lines ):
    try:
        cleanDefine = []
        record = []
        defineCheck = False
        for line in lines:
            #line = re.sub('## .*$', '', line) # Removes the ## <record type> record from parsed output
            if re.search('^## definition', line):
                defineCheck = True
                record = []
            elif re.search('^\n', line):
                defineCheck = False
                cleanDefine.append(record)
            if defineCheck:
                #line = re.sub('^# ', '', line)
                if line == '\n':
                    continue
                line = re.sub('\n', '', line)
                record.append(line)
        cleanDefine.append(record) # Grabs final record in definition records.
        return cleanDefine
    except Exception as err:
        print("\ncleanDefine() Error: {0}".format(err),"\n")
        print("With record:\n " + record)
        sys.exit()

"""
cleanSource( lines (String) ) reads in lines of the input files and "cleans" them up, removing any unnecessary new lines for
source records and returns them in a clean array.
"""
def cleanSource( lines ):
    try:
        cleanSource = []
        record = []
        sourceCheck = False
        for line in lines:
            #line = re.sub('# line: ', '', line)# Removes "# line: " from input.
            if re.search('^## source', line):
                sourceCheck = True
                record = []
            elif re.search('^\n', line):
                sourceCheck = False
                cleanSource.append(record)
            if sourceCheck:
                #line = re.sub('^# ', '', line)
                if line == '\n':
                    continue
                line = re.sub('\n', '', line)
                record.append(line)
        return cleanSource
    except Exception as err:
        print("\ncleanSource() Error: {0}".format(err),"\n")
        print("With record:\n " + record)
        sys.exit()

"""
insertFile( outputFile (Sqlite3 database), sourceFile (String) ) writes specific information from the input
file to tb_files in the seorigin db.
"""
def insertFile( outputFile, sourceFile ):
    try:
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
                pass
        database.execute('''select fileId from tb_files where Filename = ?''', File)
        fileId = database.fetchone()
        return fileId
    except Exception as err:
        print("\ninsertFile() Error: {0}".format(err),"\n")
        print("While handling file name: %s.\n" % sourceFile)
    outputFile.commit()
    database.close()

"""
insertDefinitionNames( outputFile (Sqlite3 database), definitionCall (String) ) writes specific information from the input file to tb_definitionNames in the seorigin db.
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
                pass
            database.execute('''select definitionId from tb_definitionNames 
            where DefinitionName = ?''', defName)
            definitionId = database.fetchone()
        return definitionId
    except Exception as err:
        print("\ninsertDefinitionNames() Error: {0}".format(err),"\n")
        print("While handling definition call: %s.\n" % definitionCall)
    outputFile.commit()
    database.close()

"""
insertLabel( outputFile (Sqlite3 database), label (String) ) writes specific information from the input file to tb_label in the seorigin db.
"""
def insertLabel( outputFile, label ):
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
        print("While handling label: %s.\n" % label)
    outputFile.commit()
    database.close()

"""
prepLabelset( outputFile (Sqlite3 database), labelId (integer), modifier (integer) ) is used to prepare tb_labelSet for population of tb_labelSet if no values are found inside the table.
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
insertLabelSet( outputFile (Sqlite3 database), labelSet (String) ) writes label set values to tb_labelSet based on the label set which can be one label:
            'foo_t' 
or a label set such as: 
            '{ foo_t bar_t }' 
in this case the label set would have one label set id to match the label set which would
include the labelIds of the labels inside.
"""
def insertLabelSet( outputFile, labelSet ):
    try:
        oldLabelSet = labelSet
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
                labelId = insertLabel(outputFile, label )
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
            labelSet = re.sub('[{}]', '', labelSet)
            labelSet = re.sub('\~', '', labelSet)
            labelSet = re.sub('^ ', '', labelSet)
            labelIds = []
            labels = labelSet.split()
            for label in labels:
                labelId = int(''.join(map(str, insertLabel(outputFile, label ))))
                database.execute('''select * from tb_labelSet''')
                popCheck = database.fetchone()
                if popCheck == None:
                    prepLabelSet( outputFile, (labelId,), modifier )
                labelIds.append(labelId)
            labelSetSize = len(labelIds)
            labelIds = tuple(labelIds)
            # In case we come across such label sets as: { getattr }
            if labelSetSize == 1:
                labelId = labelIds
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
                getLabelSetId = 'select labelSetId from tb_labelSet where labelId in %s group by labelSetId having count(labelId) = ?' % str(labelIds)
                database.execute(getLabelSetId, (labelSetSize, ))
                labelSetId = database.fetchone()
                if labelSetId == None:
                   database.execute('''select max(labelSetId)+1 from tb_labelSet''')
                   labelSetId = int(''.join(map(str, database.fetchone())))
                for labelId in labelIds:
                    if type(labelSetId) is tuple:
                        labelSetId = int(''.join(map(str, labelSetId)))
                    values = (labelSetId, labelId, modifier)
                    try:
                        database.execute('''insert into tb_labelSet values (?, ?, ?)''', values)
                    except sqlite3.IntegrityError:
                        pass
        if type(labelSetId) is not tuple:
            labelSetId = (labelSetId, )
        return labelSetId
    except Exception as err:
        print("\ninsertLabelSet() Error: {0}".format(err))
        print('When inserting ' + oldLabelSet + ' into tb_labelSet\n')
        sys.exit()
    outputFile.commit()
    database.close()

"""
insertStatementRule( outputFile (Sqlite3 database), line (String) ) disects the line that it is given, breaks those parts
up for proper insertion for tb_statement_rule as well as returning statementId
"""
def insertStatementRule( outputFile, line ):
    try:
        setCheck = False
        database = outputFile.cursor()
        sourceLabel = getSourceFromRule(line)
        destinationLabel = getDestinationFromRule(line)
        classesLabel = getClassesFromRule(line)
        privilegesLabel = getPrivilegesFromRule(line)
        ruleType = getRuleType(line)
        if re.search("^.*self.*$", destinationLabel):
            destinationLabel = re.sub('self', sourceLabel, destinationLabel)
        srcLabelSetId = int(''.join(map(str, insertLabelSet( outputFile, sourceLabel ))))
        dstLabelSetId = int(''.join(map(str, insertLabelSet( outputFile, destinationLabel ))))
        classLabelSetId = int(''.join(map(str, insertLabelSet( outputFile, classesLabel ))))
        prvsLabelSetId = int(''.join(map(str, insertLabelSet( outputFile, privilegesLabel ))))
        rule = (ruleType, srcLabelSetId, dstLabelSetId, classLabelSetId, prvsLabelSetId)
        database.execute('''select statementId from tb_statement_rule where RuleClass = ? and sourceId = ?
        and targetId = ? and classesId = ? and privilegeId = ?''', rule)
        statementCheck = database.fetchone()
        if statementCheck == None:
            database.execute('''insert into tb_statement_rule values (NULL, ?, ?, ?, ?, ?)''', rule)
        else:
            pass
        database.execute('''select statementId from tb_statement_rule where RuleClass = ? and sourceId = ? 
        and targetId = ? and classesId = ? and privilegeId = ?''', rule)
        statementId = database.fetchone()
        return statementId
    except Exception as err:
        print("\ninsertStatementRule() Error: {0}".format(err),"\n")
        print("While parsing line: %s.\n" % line)
    outputFile.commit()
    database.close()

"""
insertStatementAssign( outputFile (Sqlite3 database), line (String) ) disects the line that it is given, breaks those parts
up for proper insertion for tb_statement_assign as well as returning statementId
"""
def insertStatementAssign( outputFile, line ):
    try:
        assLabelId2 = 0
        database = outputFile.cursor()
        assignType = getAssignationType( line )
        assignedLabel = getAssignedFromAssignation( line )
        targetLabel = getTargetFromAssignation( line )
        tarLabelId = int(''.join(map(str, insertLabelSet( outputFile, targetLabel ))))
        assLabelId = int(''.join(map(str, insertLabelSet( outputFile, assignedLabel ))))
        values = (assignType, tarLabelId, assLabelId)
        database.execute('''select statementId from tb_statement_assign where AssignationType = ? and targetLabelId = ?
        and assignedLabelId = ?''', values)
        statementCheck = database.fetchone()
        if statementCheck == None:
            database.execute('''insert into tb_statement_assign values (NULL, ?, ?, ?)''', values)
        else:
            pass
        database.execute('''select statementId from tb_statement_assign where AssignationType = ? and targetLabelId = ? 
        and assignedLabelId = ?''', values)
        statementId = database.fetchone()
        return statementId
    except Exception as err:
        print("\ninsertStatementAssign() Error: {0}".format(err),"\n")
        print("While parsing line: %s.\n" % line)
    outputFile.commit()
    database.close()

"""
insertStatementInterface( outputFile (Sqlite3 database), line (String) ) disects the line for it's interface args as well as it's name. It gets the proper IDs for each variable and inserts them into tb_statement_interface.
Once this is done it returns the statementId.
"""
def insertStatementInterface( outputFile, line ):
    try:
        database = outputFile.cursor()
        args = getInterfaceArgs(line)
        interfaceName = getInterfaceName(line)
        interfaceId = int(''.join(map(str, insertDefinitionName(outputFile, interfaceName))))
        argId2 = 0
        argId3 = 0
        argId4 = 0
        argId5 = 0
        argId1 = int(''.join(map(str, insertLabelSet( outputFile, args[0] ))))
        try:
            argId2 = int(''.join(map(str, insertLabelSet( outputFile, args[1] ))))
            argId3 = int(''.join(map(str, insertLabelSet( outputFile, args[2] ))))
            argId4 = int(''.join(map(str, insertLabelSet( outputFile, args[3] ))))
            argId5 = int(''.join(map(str, insertLabelSet( outputFile, args[4] ))))
        except IndexError:
            pass
        values = (interfaceId, argId1, argId2, argId3, argId4, argId5)
        database.execute('''select statementId from tb_statement_interface where interfaceId = ? and 
        arg1labelId = ? and arg2labelId = ? and arg3labelId = ? and arg4labelId = ? and arg5labelId = ?''', values)
        postPopCheck = database.fetchone()
        if postPopCheck == None: 
            database.execute('''insert into tb_statement_interface values (NULL, ?, ?, ?, ?, ?, ?)''', values)
        else:
            pass
        database.execute('''select statementId from tb_statement_interface where interfaceId = ? and 
        arg1labelId = ? and arg2labelId = ? and arg3labelId = ? and arg4labelId = ? and arg5labelId = ?''', values)
        statementId = database.fetchone()
        return statementId
    except Exception as err:
        print("\ninsertStatementInterface() Error: {0}".format(err),"\n")
        print('While parsing line: ' + line)
    outputFile.commit()
    database.close()

"""
insertStatementDeclare( outputFile (Sqlite3 database), line (String) ) disects the line that it is given, breaks the line apart up for proper insertion for tb_statement_declare and returns statementId.
"""
def insertStatementDeclare( outputFile, line ):
    try:
        aliasId = 0
        database = outputFile.cursor()
        declareType = getDeclareType( line )
        targetLabel = getTargetFromDeclare( line )
        targetId = int(''.join(map(str, insertLabelSet( outputFile, targetLabel ))))
        if re.search('alias', line):
            aliasLabel = getAliasFromDeclare( line )
            aliasId = int(''.join(map(str, insertLabelSet( outputFile, aliasLabel ))))
        values = (declareType, targetId, aliasId)
        database.execute('''select statementId from tb_statement_declare where DeclarationClass = ?
        and TargetId = ? and AliasId = ?''', values)
        postPopCheck = database.fetchone()
        if postPopCheck == None:
            try:
                print(values)
                database.execute('''insert into tb_statement_declare values (NULL, ?, ?, ?)''', values)           
            except Exception as err:
                print("\ninsertStatementDeclare Error: {0}".format(err))
                print("When running Sqlite3 command:")
                print("insert into tb_statement_declare values " + str(values) + "\n")
                sys.exit()
        else:
            pass
        database.execute('''select statementId from tb_statement_declare where DeclarationClass = ?
        and TargetId = ? and AliasId = ?''', values)
        StatementId = database.fetchone()
        if not type(StatementId) == tuple:
            print("insertStatementDeclare() Error: statementId is not an int for line: %s\n" % line)
            sys.exit()
        return StatementId
    except Exception as err:
        print("\ninsertStatementDeclare() Error: {0}".format(err))
        print("While parsing line: %s\n" % line)
    outputFile.commit()
    database.close()

"""
insertStatement( outputFile (Sqlite3 database), line (String), statementType (Int) ) takes in the statementType of a line, then depending on the statementType it will call a specific insertStatement function and return the statementId for that function.
"""
def insertStatement( outputFile, line, statementType ):
    try:
        statementId = 0
        database = outputFile.cursor()
        # If we encounter a rule statement.
        if statementType == 0:
            statementId = insertStatementRule( outputFile, line )
        # If we encounter an interface statement.
        elif statementType == 1:
            insertStatementInterface( outputFile, line )
        # If we encounter an assign statement.
        elif statementType == 2:
            statementId = insertStatementAssign( outputFile, line )
        # If we enounter a declare statememt.
        elif statementType == 3:
            statementId = insertStatementDeclare( outputFile, line )
        return statementId
    except Exception as err:
        print("\ninsertStatement() Error: {0}".format(err),"\n")
        print("When parsing: %s\n" % line)

"""
writeOut( outputFile (Sqlite3 database), output (String) ) writes output to the file we want to have it outputted to. This will be included for debugging purposes.
"""
def writeOut( outputFile, output ):
    try:
        parsedOut = open(outputFile, 'w') # This assigns a new file to parsedOut
    except Exception as err:
        print("\n\nwriteOut() Error: {0}".format(err),"\n\n")
    parsedOut.write(output)
    parsedOut.close()

"""
insertSource( outputFile (Sqlite3 database), record (String list) ) calls all necessary commands required to populate tables with source record information.
"""
def insertSource( outputFile, record ):
    try:
        database = outputFile.cursor()
        if not record == []:
            fileName = getFileName( record[1] )
            fileId = insertFile( outputFile, fileName )
            if not fileId == 0:
                fileId = int(''.join(map(str, fileId )))
            if len(record) == 3:
                lineNum = getLineNumber( record[1] )
            elif len(record) == 4:
                lineNum = getLineNumber( record[2] )
            else:
                print('Unknown format of record: \n')
                for r in record:
                    print(r)
                print('\nExiting...')
                sys.exit()
            record[0] = re.sub('#', '', record[0])
            lineNum = int(''.join(map(str, lineNum )))
            recordLine = getSourceLine( record[3] )
            statementType = getStatementType(recordLine)
            statementId = insertStatement( outputFile, record[3], statementType )
            if not statementId == 0:
                statementId = int(''.join(map(str, statementId ))) 
            source = ( fileId, lineNum, statementId )
            # If we find a rule statement
            if statementType == 0:
                database.execute('''select fileId from tb_source where fileId = ? and lineNumber = ? and
                statementRuleId = ?''', source)
                popCheck = database.fetchone()
                if popCheck == None:
                    database.execute('''insert into tb_source values (?, ?, NULL, ?, NULL, NULL)''', source)
                else:
                    pass
            # If we find an interface statement
            elif statementType == 1:
                database.execute('''select fileId from tb_source where fileId = ? and lineNumber = ? and
                statementInterfaceId = ?''', source)
                popCheck = database.fetchone()
                if popCheck == None:
                    database.execute('''insert into tb_source values (?, ?, NULL, NULL, ?, NULL)''', source)
                else:
                    pass
            # If we find an assignation statement
            elif statementType == 2:
                database.execute('''select fileId from tb_source where fileId = ? and lineNumber = ? and
                statementAssignId = ?''', source)
                popCheck = database.fetchone()
                if popCheck == None:
                    database.execute('''insert into tb_source values (?, ?, NULL, NULL, NULL, ?)''', source)
                else:
                    pass
            # If we find declaration statement
            elif statementType == 3:
                database.execute('''select fileId from tb_source where fileId = ? and lineNumber = ? and
                statementDeclareId = ?''', source)
                popCheck = database.fetchone()
                if popCheck == None:
                    database.execute('''insert into tb_source values (?, ?, ?, NULL, NULL, NULL)''', source)
                else:
                    pass
    except Exception as err:
        print("insertSource() Error: {0}".format(err))
        print("While parsing" + record[0] + '.\n')
    outputFile.commit()
    database.close()

"""
cleanDefinition( outputFile (Sqlite3 database), definitionName (String) ) cleans up existing records by looking in tb_definitionName for the existing definition and Id of a definition name, then looks in tb_definition_content for all records for that Id. If it finds that content exists then it deletes all the information corressponding to that definitionId.
"""
def cleanDefinition( outputFile, definitionName ):
    try:
        database = outputFile.cursor()
        definitionName = (definitionName, )
        database.execute('''select definitionId from tb_definitionNames where definitionName = ?''', definitionName)
        definitionId = database.fetchone()
        database.execute('''select StatementDeclareId, StatementRuleId, StatementInterfaceId, StatementAssignId from 
        tb_definition_content where DefinitionId = ? ''', definitionId)
        definitionContent = database.fetchone()
        if not definitionContent == None:
            database.execute('''delete from tb_definition_content where DefinitionId = ?''', definitionId)
    except Exception:
        pass

"""
insertDefinition( outputFile (Sqlite3 database), record (String list) ) takes in the definition record, disects it for information pertaining to each necessary portion of a definition record and then populates the database with the disected information of each definition record.
"""
def insertDefinition( outputFile, record ):
    try:
        database = outputFile.cursor()
        if not record == []:
            record[0] = re.sub('#', '', record[0])
            defName = getDefinitionName( record[1] )
            cleanDefinition( outputFile, defName )
            definitionId = insertDefinitionName(outputFile, defName)
            if type(definitionId) == tuple:
                definitionId = int(''.join(map(str, definitionId)))
            if not type(definitionId) == int:
                print("insertDefinition() Error: definitionId is not of type int\nWhile handling definition name: %s\n" % defName)
                sys.exit()
            for record in record[2:]:
                LineType = getStatementType(record)
                # If we enounter a rule statememt.
                if LineType == 0:
                    statementId = insertStatementRule( outputFile, record )
                    if type(statementId) == tuple:
                        statementId = int(''.join(map(str, statementId)))
                    if not type(statementId) == int:
                        print("insertDefinition() Error: statementId is not of type int\nWhile parsing line: %s.\n" % record)
                        sys.exit()
                    content = (definitionId, statementId )
                    database.execute('''insert into tb_definition_content values 
                    (?, NULL, ?, NULL, NULL)''', content)
                # If we encounter an interface statement.
                elif LineType == 1:
                    statementId = insertStatementInterface( outputFile, record )
                    if type(statementId) == tuple:
                        statementId = int(''.join(map(str, statementId)))
                    if not type(statementId) == int:
                        print("insertDefinition() Error: statementId is not of type int\nWhile parsing line: %s.\n" % record)
                        sys.exit()
                    content = (definitionId, statementId, )
                    database.execute('''insert into tb_definition_content values
                    (?, NULL, NULL, ?, NULL)''', content)
                # If we encounter an assignation statement.
                elif LineType == 2:
                    statementId = insertStatementAssign( outputFile, record )
                    if type(statementId) == tuple:
                        statementId = int(''.join(map(str, statementId)))
                    if not type(statementId) == int:
                        print("insertDefinition() Error: statementId is not of type int\nWhile parsing line: %s.\n" % record)
                        sys.exit()
                    content = (definitionId, statementId, )
                    database.execute('''insert into tb_definition_content values
                    (?, NULL, NULL, NULL, ?)''', content)
                # If we encounter a declaration statement.
                elif LineType == 3:
                    statementId = insertStatementDeclare( outputFile, record )
                    if type(statementId) == tuple:
                        statementId = int(''.join(map(str, statementId)))
                    if not type(statementId) == int:
                        print("insertDefinition() Error: statementId is not of type int\nWhile parsing line: %s.\n" % record)
                        sys.exit()
                    content = (definitionId, statementId, )
                    database.execute('''insert into tb_definition_content values
                    (?, ?, NULL, NULL, NULL)''', content)
    except Exception as err:
        print("insertDefinition() Error: {0}".format(err))
        print("While parsing" + record[0] +'.\n')
    outputFile.commit()
    database.close()

"""
seorigin( outputFile (Sqlite3 database), lines (String) ) creates the seorigin database by calling the necessary functions to create and write the seorigin database.
"""
def seorigin( outputFile, lines ):
    try:
        createTables( outputFile )
        source_record = cleanSource( lines )
        definition_record = cleanDefine( lines )

        for record in definition_record:
            insertDefinition( outputFile, record )
        for record in source_record:
            insertSource( outputFile, record )

    except Exception as err:
        print("seorigin() Error: {0}".format(err),"\n")
        usage()

"""
main() is where all the magic happens! Like Disney land, just less...'cartooney'.
"""
def main():
    print("Workflow component v1.2.7: \n")
    print("Please be patient, this MAY take awhile...")
    (inputFile, outputFile) = parse_cmd_args()
    lines = readInput( inputFile )
    seorigin( outputFile, lines )
    print("Enjoy your fresh new database! Be careful, it may be hot. ;)\n")

"""
The main function is run below.
"""
if __name__ == "__main__":
    main()
