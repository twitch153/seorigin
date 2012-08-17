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

#TODO find range in range_transition statements such as:
# range_transition $1 initrc_exec_t:process s0 - mls_systemhigh
# understand what they mean and how to handle them.
# Add -d flag for debugging.

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
    elif re.search('^if', line):
        pass
    elif line == '':
        pass
    # Checks for rule calls
    elif re.search('^allow .*:.*;', line):
        statementValue = 0
    elif re.search('^type_change', line):
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
    elif re.search('^allow ', line):
        statementValue = 2
    # Checks for declaration calls
    elif re.search('^type ', line):
        statementValue = 3
    elif re.search('^role ', line):
        statementValue = 3
    elif re.search('^attribute', line):
        statementValue = 3
    elif re.search('^\{', line):
        statementValue = 3
    # Checks for role_transition calls
    elif re.search('^role_transition', line):
        statementValue = 4
    # Checks for type_transition calls
    elif re.search('^type_transition', line):
        statementValue = 5
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
        print("getDeclareType() Error: {0}".format(err))
        print("While determining type of line: %s" % declareLine,"\n")

"""
getRuleType( ruleLine (String) ) goes through the lines of rules statements and returns the rule type as an int.
"""
def getRuleType( ruleLine ):
    try:
        ruleType = 0
        if re.search('^allow', ruleLine):
            ruleType = 1
        elif re.search('^dontaudit', ruleLine):
            ruleType = 2
        elif re.search('^auditallow', ruleLine):
            ruleType = 3
        elif re.search('^range_transition', ruleLine):
            ruleType = 4
        elif re.search('^neverallow', ruleLine):
            ruleType = 5
        elif re.search('^type_member', ruleLine):
            ruleType = 6
        elif re.search('^type_change', ruleLine):
            ruleType = 7
        return ruleType
    except Exception as err:
        print("getRuleType() Error: {0}".format(err))
        print("While determining rule type of line: %s" % ruleLine,"\n")

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
        elif re.search('^allow', assignLine):
            assignType = 7
        return assignType
    except Exception as err:
        print('\ngetAssignationType() Error: {0}'.format(err))
        print("While determining assignment type from: %s.\n" % assignLine)

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
getFileName( record (String) ) goes through a source record and returns the file name.
"""
def getFileName( record ):
    try:
        sourceFile = ''
        oldRecord = record
        if re.search('^# \w+/.*$', record):
            record = re.sub('^# ', '', record)
            sourceFile = record
        return sourceFile
    except Exception as err:
        print("\ngetFileName Error: {0}".format(err))
        print("While parsing file name from line: %s" % oldRecord,"\n")

"""
getDefinitionName( record (String) ) goes through a definition record and returns the definition name.
"""
def getDefinitionName( record ):
    try:
        definitionName = ''
        oldRecord = record
        if re.search('^# ', record):
            record = re.sub('^# ', '', record)
            definitionName = record
        return definitionName
    except Exception as err:
        print("\ngetDefinitionName() Error: {0}".format(err))
        print("While parsing definition name from line: %s" % oldRecord,"\n")

"""
getSourceLine( record (String) ) detects the source line of a source record, parses it out using regular expressions,
then returns it.
"""
def getSourceLine( record ):
    try:
        recordLine = ''
        sourceCheck = False
        oldRecord = record
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
    except Exception as err:
        print("\ngetSourceLine() Error: {0}".format(err))
        print("While parsing source line from line: %s" % oldRecord,"\n")
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
        if re.search('^ ', line):
            line = re.sub('^ ', '', line)
        oldLine = line
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
        print('\ngetSourceFromRule() Error{0}'.format(err))
        print("While parsing source from line: %s" % oldLine,"\n")

"""
getDestinationFromRule( line (String) ) goes through a rule statement such as this:

    "allow $1 $2:file { mmap_file_perms ioctl lock };"

and would return the destination label which in this case would be: $2.
"""
def getDestinationFromRule( line ):
    try:
        destination = ''
        setCheck = False
        if re.search('^ ', line):
            line = re.sub('^ ', '', line)
        line = re.sub(':.*$', '', line)
        if re.search('{', line):
            setCheck = True
        elif re.search('}', line):
            setCheck = False
        if setCheck:
            destination = re.sub('^\w+[_\w+] ', '', line)
            if re.search('^\w+_\$\d+_\w+ ', destination):
                destination = re.sub('^\w+_\$\d+_\w+ ', '', destination)
            if re.search('^\$\d+[_w+]', destination):
                destination = re.sub('^\$\d+_\w+ ', '', destination)
            elif re.search('^\$\d+', destination):
                destination = re.sub('^\$\d+ ', '', destination)
            elif re.search('^\$\d+[_w+]', destination):
                destination = re.sub('^\$\d+_\w+ ', '', destination)
            elif re.search('^\w+', destination):
                destination = re.sub('^\w+ ', '', destination)
            elif re.search('^[~{].*} ', destination):
                destination = re.sub('^[~{].*} ', '', destination)
        else:
            destination = re.sub('^\w+[_\w+] ', '', line)
            if re.search('^\w+_\$\d+_\w+ ', destination):
                destination = re.sub('^\w+_\$\d+_\w+ ', '', destination)
            if re.search('^\$\d+[_w+]', destination):
                destination = re.sub('^\$\d+_\w+ ', '', destination)
            elif re.search('^\$\d+', destination):
                destination = re.sub('^\$\d+ ', '', destination)
            elif re.search('^\w+', destination):
                destination = re.sub('^\w+ ', '', destination)
            elif re.search('^[~{].*} ', destination):
                destination = re.sub('^[~{].*} ', '', destination)
        return destination
    except Exception as err:
        print("getDestinationFromRule() Error: {0}".format(err))
        print("While parsing destination from line: %s" % oldLine,'\n')

"""
getClassFromRule( line (String) ) goes through a rule statement such as this:

    "allow $1 $2:file { mmap_file_perms ioctl lock };"

and would return the destination label which in this case would be: file.
"""
def getClassesFromRule( line ):
    try:
        classes = ''
        setCheck = False
        oldLine = line
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
    except Exception as err:
        print("\ngetClassFromRule() Error: {0}".format(err))
        print("While parsing classes from line: %s" % oldLine,"\n")

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
        oldLine = line
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
        print("\ngetPrivilegesFromRule() Error{0}".format(err))
        print("While parsing privileges from line: %s" % oldLine,'\n')

"""
getInterfaceArgs( line (String) ) reads in the line of an interface statement and returns in interface
arguments as a list. 
If we get an interface statement such as:
    domain_entry_file($1,$2)
We would return the arguments in as list like: ['$1', '$2']
"""
def getInterfaceArgs( line ):
    try:
        oldLine = line
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
        print('\ngetInterfaceArgs() Error: {0}'.format(err))
        print("While parsing interface args from line: %s" % line,'\n')

'''
getInterfaceName( interfaceLine (String) ) grabs the name of the interface statement and returns the name as a string
'''
def getInterfaceName( interfaceLine ):
    try:
        name = ''
        if re.search('^ ', interfaceLine):
            interfaceLine = re.sub('^ *', '', interfaceLine)
        name = re.sub('\(.*\)', '', interfaceLine)
        return name
    except Exception as err:
        print('\ngetInterfaceName() Error: {0}'.format(err))
        print("While parsing interface name from line: %s" % interfaceLine,"\n")

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
        oldLine = line
        line = re.sub('^ ', '', line)
        line = re.sub('^\w+ ', '', line)
        target = re.sub(' .*;', '', line)
        target = re.sub('[, ]', '', target)
        return target
    except Exception as err:
        print('\ngetTargetFromAssignation() Error: {0}'.format(err))
        print("While parsing Target from line: %s " % oldLine,"\n")

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
        assigned = re.sub('^ ', '', line)
        assigned = re.sub('^\w+ ', '', assigned)
        if re.search('^\w+[_\w+]', assigned):
            assigned = re.sub('^\w+[_\w+] ', '', assigned)
        elif re.search('^\$\d+[_\w+]', assigned):
            assigned = re.sub('^\$\d+_\w+ ', '', assigned)
        elif re.search('^\$\d+', assigned):
            assigned = re.sub('^\$\d+ ', '', assigned)
        if re.search('^\w+_\$\d+_\w+ ', assigned):
            assigned = re.sub('^\w+_\$\d+_\w+ ', '', assigned)
        assigned = re.sub('^types ', '', assigned)
        if re.search('^alias', assigned):
            assigned = re.sub('^alias ', '', assigned)
        if re.search('^.*, .*', assigned):
            assigned = re.sub(',', '', assigned)
            assigned = re.sub('^', '{ ', assigned)
            assigned = re.sub(';', ' }', assigned)
        else:
            assigned = re.sub(';', '', assigned)
        return assigned
    except Exception as err:
        print('\ngetAssignedFromAssignation() Error: {0}'.format(err))
        print("While parsing assigned from line: %s" % line,"\n")

'''
getTargetFromDeclare( declareLine (String) ) takes in a declaration line such as:
    role system_r
and returns the target of the declaration, which would be: system_r
'''
def getTargetFromDeclare( declareLine ):
    try:
        target = ''
        oldDeclare = declareLine
        if re.search('^ ', declareLine):
            declareLine = re.sub('^ ', '', declareLine)
        target = re.sub('^\w+[_\w+] ', '', declareLine)
        target = re.sub(' alias .*$', '', target)
        target = re.sub(';', '', target)
        return target 
    except Exception as err:
        print("\ngetTargetFromDeclare() Error: {0}".format(err))
        print("While parsing target from line: %s.\n" % oldDeclare)

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
        print('\ngetAliasFromDeclare() Error: {0}'.format(err))
        print("While parsing alias from line: %s.\n" % declareLine)

'''
getArgFromRoleTrans( roleTransLine (String) ) takes in a role_transition line like:
    role_transition $2 amavis_initrc_exec_t system_r;
and returns the argument which in this case would be: $2
'''
def getArgFromRoleTrans( roleTransLine ):
    try:
        arg = ''
        if re.search('^ ', roleTransLine ):
            roleTransLine = re.sub('^ *', '', roleTransLine )
        oldLine = roleTransLine
        arg = re.sub('role_transition ', '', roleTransLine)
        arg = re.sub(' .*_t', '', arg)
        arg = re.sub(' .*_r;', '', arg)
        return arg
    except Exception as err:
        print('\ngetArgFromRoleTrans() Error: {0}'.format(err))
        print('While parsing argument from line: %s.\n' % oldLine)

'''
getTypeFromRoleTrans( roleTransLine (String) ) takes in a role_transition line like:
    role_transition $2 amavis_initrc_exec_t system_r;
and returns the target which in this case would be: amavis_initrc_exec_t
'''
def getTypeFromRoleTrans( roleTransLine ):
    try:
        roleTransTarget = ''
        if re.search('^ ', roleTransLine ):
            roleTransLine = re.sub('^ *', '', roleTransLine )
        oldLine = roleTransLine
        roleTransTarget = re.sub('^role_transition ', '', roleTransLine)
        if re.search('^\$\d+[_\w+]', roleTransTarget):
            roleTransTarget = re.sub('^\$\d+_\w+ ', '', roleTransTarget)
        elif re.search('^\$\d+', roleTransTarget):
            roleTransTarget = re.sub('^\$\d+ ', '', roleTransTarget)
        if re.search('^\w+_\$\d+_\w+ ', roleTransTarget):
            roleTransTarget = re.sub('^\w+_\$\d+_\w+ ', '', roleTransTarget)
        elif re.search('^\w+[_\w+]', roleTransTarget):
            roleTransTarget = re.sub('^\w+[_\w+] ', '', roleTransTarget)
        roleTransTarget = re.sub(' .*_r;', '', roleTransTarget)
        return roleTransTarget
    except Exception as err:
        print('\ngetTypeFromRoleTrans() Error: {0}'.format(err))
        print('While parsing type from line: %s.\n' % oldLine)

'''
getRoleFromRoleTrans( roleTransLine (String) ) takes in a role_transition line like:
    role_transition $2 amavis_initrc_exec_t system_r;
and returns the assignation which in this case would be: system_r
'''
def getRoleFromRoleTrans( roleTransLine ):
    try:
        roleTransAssign = ''
        if re.search('^ ', roleTransLine ):
            roleTransLine = re.sub('^ *', '', roleTransLine )
        oldLine = roleTransLine
        roleTransAssign = re.sub('^role_transition .*\w+ ', '', roleTransLine)
        roleTransAssign = re.sub(';', '', roleTransAssign)
        return roleTransAssign
    except Exception as err:
        print('\ngetTypeFromRoleTrans() Error: {0}'.format(err))
        print('While parsing role from line: %s.\n' % oldLine)

'''
getSourceFromTypeTrans( typeTransLine (String) ) takes in a type_transition line like:
    type_transition $2 input_xevent_t:x_event $1_input_xevent_t;
and returns the source which in this case would be: $2
'''
def getSourceFromTypeTrans( typeTransLine ):
    try:
        source = ''
        if re.search('^ ', typeTransLine ):
            typeTransLine = re.sub('^ *', '', typeTransLine)
        source = re.sub('^type_transition ', '', typeTransLine)
        source = re.sub(':.*$', ':', source)
        source = re.sub(' .*:', '', source)
        return source
    except Exception as err:
        print("\ngetSourceFromTypeTrans() Error: {0}".format(err))
        print("While parsing source from line: %s" % typeTransLine,"\n")

'''
getResourceFromTypeTrans( typeTransLine (String) ) takes in a type_transition line like:
    type_transition $2 input_xevent_t:x_event $1_input_xevent_t;
and returns the resource which in this case would be: input_xevent_t
'''
def getResourceFromTypeTrans( typeTransLine ):
    try:
        resource = ''
        if re.search('^ ', typeTransLine ):
            typeTransLine = re.sub('^ *', '', typeTransLine)
        resource = re.sub('^type_transition ', '', typeTransLine)
        resource = re.sub(':.*$', '', resource)
        resource = re.sub(' ', ':', resource)
        resource = re.sub('.*:', '', resource)
        return resource
    except Exception as err:
        print("\ngetResourceFromTypeTrans() Error: {0}".format(err))
        print("While parsing resource from line: %s" % typeTransLine,"\n")

'''
getTargetFromTypeTrans( typeTransLine (String) ) takes in a type_transition line like:
    type_transition $2 input_xevent_t:x_event $1_input_xevent_t;
and returns the target which in this case would be: x_event
'''
def getTargetFromTypeTrans( typeTransLine ):
    try:
        target = ''
        setCheck = False
        if re.search('^ ', typeTransLine ):
            typeTransLine = re.sub('^ *', '', typeTransLine)
        target = re.sub('^type_transition ', '', typeTransLine)
        target = re.sub('.*:', '', target)
        if re.search('^{', target):
            target = re.sub('}.*$', '}', target)
        else:
            target = re.sub(' .*$', '', target)
        return target
    except Exception as err:
        print("\ngetTargetFromTypeTrans() Error: {0}".format(err))
        print("While parsing target from line: %s" % typeTransLine,"\n")

'''
getClassFromTypeTrans( typeTransLine (String) ) takes in a type_transition line like:
    type_transition $2 input_xevent_t:x_event $1_input_xevent_t;
and returns the class which in this case would be: $1_input_xevent_t
'''
def getClassFromTypeTrans( typeTransLine ):
    try:
        Class = ''
        if re.search('^ ', typeTransLine ):
            typeTransLine = re.sub('^ *', '', typeTransLine)
        Class = re.sub('^type_transition ', '', typeTransLine)
        Class = re.sub('.*:', '', Class)
        if re.search('^\$\d+[_\w+]', Class):
            Class = re.sub('^\$\d+_\w+ ', '', Class)
        elif re.search('^\$\d+', Class):
            Class = re.sub('^\$\d+ ', '', Class)
        if re.search('^\w+_\$\d+_\w+ ', Class):
            Class = re.sub('^\w+_\$\d+_\w+ ', '', Class)
        elif re.search('^\w+[_\w+]', Class):
            Class = re.sub('^\w+[_\w+] ', '', Class)
        elif re.search('^{', Class):
            Class = re.sub('{.*} ', '', Class)
        if re.search('.* .*', Class):
            Class = re.sub(' .*;', '', Class)
        else:
            Class = re.sub(';', '', Class)
        return Class
    except Exception as err:
        print("\ngetClassFromTypeTrans() Error: {0}".format(err))
        print("While parsing class from line: %s" % typeTransLine,"\n")

'''
getFileFromTypeTrans( typeTransLine (String) ) takes in a type_transition line like:
    type_transition $1 sepgsql_database_type:db_schema sepgsql_temp_object_t "pg_temp";
and returns the file which in this case would be: "pg_tep"
'''
def getFileFromTypeTrans( typeTransLine ):
    try:
        File = ''
        if re.search('^ ', typeTransLine ):
            typeTransLine = re.sub('^ *', '', typeTransLine)
        File = re.sub('.*:', '', typeTransLine)
        if re.search('^\$\d+[_\w+]', File):
            File = re.sub('^\$\d+_\w+ ', '', File)
        elif re.search('^\$\d+', File):
            File = re.sub('^\$\d+ ', '', File)
        if re.search('^\w+_\$\d+_\w+ ', File):
            File = re.sub('^\w+_\$\d+_\w+ ', '', File)
        elif re.search('^\w+[_\w+]', File):
            File = re.sub('^\w+[_\w+] ', '', File)
        elif re.search('^{', File):
            File = re.sub('{.*} ', '', File)
        if re.search('.* .*', File):
            File = re.sub('.* ', '', File)
            File = re.sub(';', '', File)
        else:
            File = '' # No file label found.
        return File
    except Exception as err:
        print("\ngetFileFromTypeTrans() Error: {0}".format(err))
        print("While parsing file name from line: %s" % typeTransLine,"\n")

"""
getClassList() grabs the information from "SELinux Class list" and returns it as a list.
"""
def getClassList():
    try:
        if os.path.exists(os.path.join(os.environ["PWD"], 'SELinux_Class_list.txt')):
            classList = readInput(os.path.join(os.environ["PWD"], 'SELinux_Class_list.txt'))
            if not os.access(os.path.join(os.environ["PWD"], 'SELinux_Class_list.txt'), os.R_OK):
                print("\nFile SELinux_Class_list.txt does not have read permissions!\nPlease change file permissions.\n")
                sys.exit()
        else:
            print("Critical Error!: SELinux_Class_list.txt not found in " + os.path.join(os.environ["PWD"]))
            print("Please be sure it is under the correct name and in the present working directory.\n")
            sys.exit()
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
    try:
        if os.path.exists(os.path.join(os.environ["PWD"], 'SELinux_Perms_list.txt')):
            permsList = readInput(os.path.join(os.environ["PWD"], 'SELinux_Perms_list.txt'))
            if not os.access(os.path.join(os.environ["PWD"], 'SELinux_Perms_list.txt'), os.R_OK):
                print("\nFile SELinux_Perms_list.txt does not have read permissions!\nPlease change file permissions.\n")
                sys.exit()
        else:
            print("Critical Error!: SELinux_Perms_list.txt not found in " + os.path.join(os.environ["PWD"]))
            print("Please be sure it is under the correct name and in the present working directory.\n")
            sys.exit()
        result = ['']
        for List in permsList:
            List = re.sub('\n', '', List)
            result.append(List)
        return result
    except Exception as err:
        print("\ngetPermList() Error: {0}".format(err),"\n")

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

        database.execute('''create table if not exists tb_statement_roletrans
        (StatementId INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, ArgId INTEGER NOT NULL,
        TypeId INTEGER NOT NULL, RoleId INTEGER NOT NULL, FOREIGN KEY(ArgId) 
        REFERENCES TB_LABELSET(LabelSetId), FOREIGN KEY(TypeId) REFERENCES TB_LABELSET(LabelSetId),
        FOREIGN KEY(RoleId) REFERENCES TB_LABELSET(LabelSetId))''')

        database.execute('''create table if not exists tb_statement_typetrans
        (StatementId INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, SourceId INTEGER NOT NULL,
        ResourceId INTEGER NOT NULL, TargetId INTEGER NOT NULL, ClassId INTEGER NOT NULL,
        FileId INTEGER, FOREIGN KEY(SourceId) REFERENCES TB_LABELSET(LabelSetId),
        FOREIGN KEY(ResourceId) REFERENCES TB_LABELSET(LabelSetId), FOREIGN KEY(TargetId)
        REFERENCES TB_LABELSET(LabelSetId), FOREIGN KEY(ClassId) REFERENCES TB_LABELSET(LabelSetId),
        FOREIGN KEY(FileId) REFERENCES TB_LABELSET(LabelSetId))''') 

        database.execute('''create table if not exists tb_definition_content
        (DefinitionId INTEGER NOT NULL, StatementDeclareId INTEGER, StatementRuleId INTEGER,
        StatementInterfaceId INTEGER, StatementAssignId INTEGER, StatementRoleTransId, StatementTypeTransId, 
        FOREIGN KEY(DefinitionId) REFERENCES TB_DEFINITIONNAMES(DefinitionId), 
        FOREIGN KEY(StatementDeclareId) REFERENCES TB_STATEMENT_DECLARE(StatementId), 
        FOREIGN KEY(StatementRuleId) REFERENCES TB_STATEMENT_RULE(StatementId), 
        FOREIGN KEY(StatementInterfaceId) REFERENCES TB_STATEMENT_INTERFACE(StatementId), 
        FOREIGN KEY(StatementAssignId) REFERENCES TB_STATEMENT_ASSIGN(StatementId)
        FOREIGN KEY(StatementRoleTransId) REFERENCES TB_STATEMENT_ROLETRANS(StatementId)
        FOREIGN KEY(StatementTypeTransId) REFERENCES TB_STATEMENT_TYPETRANS(StatementId))''')
    
        database.execute('''create table if not exists tb_source
        (FileId INTEGER NOT NULL, LineNumber INTEGER NOT NULL, StatementDeclareId INTEGER,
        StatementRuleId INTEGER, StatementInterfaceId INTEGER, StatementAssignId INTEGER,
        StatementRoleTransId INTEGER, StatementTypeTransId INTEGER, 
        FOREIGN KEY(StatementDeclareId) REFERENCES TB_STATEMENT_DECLARE(StatementId), 
        FOREIGN KEY(StatementRuleId) REFERENCES TB_STATEMENT_RULE(StatementId),
        FOREIGN KEY(StatementInterfaceId) REFERENCES TB_STATEMENT_INTERFACE(StatementId),
        FOREIGN KEY(StatementAssignId) REFERENCES TB_STATEMENT_ASSIGN(StatementId),
        FOREIGN KEY(StatementRoleTransId) REFERENCES TB_STATEMENT_ROLETRANS(StatementId)
        FOREIGN KEY(StatementTypeTransId) REFERENCES TB_STATEMENT_TYPETRANS(StatementId))''')

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
        cleanSource.append(record) # Grabs final source record.
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
            sourceFile = (sourceFile, )
            database.execute('''select * from tb_files where Filename = ?''', sourceFile)
            postPopCheck = database.fetchone()
            if postPopCheck == None:
                database.execute('''insert into tb_files values (NULL, ?)''', sourceFile)
            else:
                pass
        database.execute('''select fileId from tb_files where Filename = ?''', sourceFile)
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
        if re.search(' $', definitionCall):
            definitionCall = re.sub(' *$', '', definitionCall)
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
        if re.search('^ ', label):
            label = re.sub('^ ', '', label)
        if re.search(' $', label):
            label = re.sub(' $', '', label)
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
        print("\ninsertStatementAssign() Error: {0}".format(err))
        print("While parsing line: %s\n" % line)
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
insertStatementDeclare( outputFile (Sqlite3 database), line (String) ) disects the line that it is given for information necessary for proper insertion for tb_statement_declare and returns statementId.
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

'''
insertStatementRoleTrans( outputFile (Sqlite3 database), line (String) ) disects the given line for information pertaining to the role_transition statement and then populates tb_statement_roletrans with that information.
'''
def insertStatementRoleTrans( outputFile, line ):
    try:
        database = outputFile.cursor()
        argLabel = getArgFromRoleTrans( line )
        targetLabel = getTypeFromRoleTrans( line )
        assignLabel = getRoleFromRoleTrans( line )
        targetId = int(''.join(map(str, insertLabelSet( outputFile, targetLabel ))))
        argId = int(''.join(map(str, insertLabelSet( outputFile, argLabel ))))
        assignId = int(''.join(map(str, insertLabelSet( outputFile, assignLabel ))))
        values = (argId, targetId, assignId)
        database.execute('''select * from tb_statement_roletrans where ArgId = ? and TypeId = ?
        and RoleId = ?''', values)
        postPopCheck = database.fetchone()
        if postPopCheck == None:
            try:
                database.execute('''insert into tb_statement_roletrans values (NULL, ?, ?, ?)''', values)
            except Exception as err:
                print('\insertStatementRoleTrans() Error{0}'.format(err))
                print('When running Sqlite3 command:')
                print('insert into tb_statement_roletrans values ' + str(values) + '\n')
        else:
            pass
        database.execute('''select statementId from tb_statement_roletrans where ArgId = ? 
        and TypeId = ? and RoleId = ?''', values)
        statementId = database.fetchone()
        if not type(statementId) == tuple:
            print("insertStatementRoleTrans() Error: statementId is not of type int for line: %s\n" % line)
            sys.exit()
        return statementId
    except Exception as err:
        print('\ninsertStatementRoleTrans() Error: {0}'.format(err))
        print('While parsing line: %s\n' % line)
    outputFile.commit()
    database.close()

'''
insertStatementTypeTrans( outputFile (Sqlite3 database), line (String) ) disects the given line for information pertaining to the type_transition statement and then populates tb_statement_typetrans with that information.
'''
def insertStatementTypeTrans( outputFile, line ):
    try:
        fileId = 0
        database = outputFile.cursor()
        sourceLabel = getSourceFromTypeTrans( line )
        resourceLabel = getResourceFromTypeTrans( line )
        targetLabel = getTargetFromTypeTrans( line )
        classLabel = getClassFromTypeTrans( line )
        fileLabel = getFileFromTypeTrans( line )
        sourceId = int(''.join(map(str, insertLabelSet( outputFile, sourceLabel ))))
        resourceId = int(''.join(map(str, insertLabelSet( outputFile, resourceLabel ))))
        targetId = int(''.join(map(str, insertLabelSet( outputFile, targetLabel ))))
        classId = int(''.join(map(str, insertLabelSet( outputFile, classLabel ))))
        if not fileLabel == '':
            fileId = int(''.join(map(str, insertLabelSet( outputFile, fileLabel ))))
        values = (sourceId, resourceId, targetId, classId, fileId)
        database.execute('''select * from tb_statement_typetrans where SourceId = ? and ResourceId = ?
        and TargetId = ? and ClassId = ? and FileId = ?''', values)
        postPopCheck = database.fetchone()
        if postPopCheck == None:
            database.execute('''insert into tb_statement_typetrans values(NULL, ?, ?, ?, ?, ?)''', values)
        else:
            pass
        database.execute('''select StatementId from tb_statement_typetrans where SourceId = ? and ResourceId = ?
        and TargetId = ? and ClassId = ? and FileId = ?''', values)
        statementId = database.fetchone()
        if type(statementId) == tuple:
            statementId = int(''.join(map(str, statementId)))
        if not type(statementId) == int:
            print("\ninsertStatementTypeTrans() Error: statementId is not of type int for line: %s" % line)
            sys.exit()
        return statementId 
    except Exception as err:
        print("insertStatementTypeTrans() Error: {0}".format(err))
        print("While parsing line: %s" % line,"\n")
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
            statementId = insertStatementInterface( outputFile, line )
        # If we encounter an assign statement.
        elif statementType == 2:
            statementId = insertStatementAssign( outputFile, line )
        # If we enounter a declare statememt.
        elif statementType == 3:
            statementId = insertStatementDeclare( outputFile, line )
        # If we encounter a role_transition statement.
        elif statementType == 4:
            statementId = insertStatementRoleTrans( outputFile, line )
        # If we encounter a type_transition statement.
        elif statementType == 5:
            statementId = insertStatementTypeTrans( outputFile, line )
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
                    database.execute('''insert into tb_source values (?, ?, NULL, ?, NULL, NULL, NULL, NULL)''', source)
                else:
                    pass
            # If we find an interface statement
            elif statementType == 1:
                database.execute('''select fileId from tb_source where fileId = ? and lineNumber = ? and
                statementInterfaceId = ?''', source)
                popCheck = database.fetchone()
                if popCheck == None:
                    database.execute('''insert into tb_source values (?, ?, NULL, NULL, ?, NULL, NULL, NULL)''', source)
                else:
                    pass
            # If we find an assignation statement
            elif statementType == 2:
                database.execute('''select fileId from tb_source where fileId = ? and lineNumber = ? and
                statementAssignId = ?''', source)
                popCheck = database.fetchone()
                if popCheck == None:
                    database.execute('''insert into tb_source values (?, ?, NULL, NULL, NULL, ?, NULL, NULL)''', source)
                else:
                    pass
            # If we find declaration statement
            elif statementType == 3:
                database.execute('''select fileId from tb_source where fileId = ? and lineNumber = ? and
                statementDeclareId = ?''', source)
                popCheck = database.fetchone()
                if popCheck == None:
                    database.execute('''insert into tb_source values (?, ?, ?, NULL, NULL, NULL, NULL, NULL)''', source)
                else:
                    pass
            # If we find role_transition statement
            elif statementType == 4:
                database.execute('''select fileId from tb_source where fileId = ? and lineNumber = ? and
                statementRoleTransId = ?''', source)
                popCheck = database.fetchone()
                if popCheck == None:
                    database.execute('''insert into tb_source values (?, ?, NULL, NULL, NULL, NULL, ?, NULL)''', source)
                else:
                    pass
            # If we find type_transition statement
            elif statementType == 5:
                database.execute('''select fileId from tb_source where fileId = ? and lineNumber = ? and
                statementTypeTransId = ?''', source)
                popCheck = database.fetchone()
                if popCheck == None:
                    database.execute('''insert into tb_source values (?, ?, NULL, NULL, NULL, NULL, NULL, ?)''', source)
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
        database.execute('''select StatementDeclareId, StatementRuleId, StatementInterfaceId, StatementAssignId,
         StatementRoleTransId, StatementTypeTransId from tb_definition_content where DefinitionId = ? ''', definitionId)
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
                    database.execute('''select * from tb_definition_content where definitionId = ?
                    and statementRuleId = ?''', content)
                    postPopCheck = database.fetchone()
                    if postPopCheck == None:
                        database.execute('''insert into tb_definition_content values 
                        (?, NULL, ?, NULL, NULL, NULL, NULL)''', content)
                # If we encounter an interface statement.
                elif LineType == 1:
                    statementId = insertStatementInterface( outputFile, record )
                    if type(statementId) == tuple:
                        statementId = int(''.join(map(str, statementId)))
                    if not type(statementId) == int:
                        print("insertDefinition() Error: statementId is not of type int\nWhile parsing line: %s.\n" % record)
                        sys.exit()
                    content = (definitionId, statementId, )
                    database.execute('''select * from tb_definition_content where definitionId = ?
                    and statementInterfaceId = ?''', content)
                    postPopCheck = database.fetchone()
                    if postPopCheck == None:
                        database.execute('''insert into tb_definition_content values
                        (?, NULL, NULL, ?, NULL, NULL, NULL)''', content)
                # If we encounter an assignation statement.
                elif LineType == 2:
                    statementId = insertStatementAssign( outputFile, record )
                    if type(statementId) == tuple:
                        statementId = int(''.join(map(str, statementId)))
                    if not type(statementId) == int:
                        print("insertDefinition() Error: statementId is not of type int\nWhile parsing line: %s.\n" % record)
                        sys.exit()
                    content = (definitionId, statementId, )
                    database.execute('''select * from tb_definition_content where definitionId = ?
                    and statementAssignId = ?''', content)
                    postPopCheck = database.fetchone()
                    if postPopCheck == None:
                        database.execute('''insert into tb_definition_content values
                        (?, NULL, NULL, NULL, ?, NULL, NULL)''', content)
                # If we encounter a declaration statement.
                elif LineType == 3:
                    statementId = insertStatementDeclare( outputFile, record )
                    if type(statementId) == tuple:
                        statementId = int(''.join(map(str, statementId)))
                    if not type(statementId) == int:
                        print("insertDefinition() Error: statementId is not of type int\nWhile parsing line: %s.\n" % record)
                        sys.exit()
                    content = (definitionId, statementId, )
                    database.execute('''select * from tb_definition_content where definitionId = ?
                    and statementDeclareId = ?''', content)
                    postPopCheck = database.fetchone()
                    if postPopCheck == None:
                        database.execute('''insert into tb_definition_content values
                        (?, ?, NULL, NULL, NULL, NULL, NULL)''', content)
                # If we encounter a role_transition statement.
                elif LineType == 4:
                    statementId = insertStatementRoleTrans( outputFile, record )
                    if type(statementId) == tuple:
                        statementId = int(''.join(map(str, statementId)))
                    if not type(statementId) == int:
                        print("insertDefinition() Error: statementId is not of type int\nWhile parsing line: %s.\n" % record)
                        sys.exit()
                    content = (definitionId, statementId, )
                    database.execute('''select * from tb_definition_content where definitionId = ?
                    and statementRoleTransId = ?''', content)
                    postPopCheck = database.fetchone()
                    if postPopCheck == None:
                        database.execute('''insert into tb_definition_content values
                        (?, NULL, NULL, NULL, NULL, ?, NULL)''', content)
                # If we encounter a type_transition statement.
                elif LineType == 5:
                    statementId = insertStatementTypeTrans( outputFile, record )
                    if type(statementId) == tuple:
                        statementId = int(''.join(map(str, statementId)))
                    if not type(statementId) == int:
                        print("insertDefinition() Error: statementId is not of type int\nWhile parsing line: %s.\n" % record)
                        sys.exit()
                    content = (definitionId, statementId, )
                    database.execute('''select * from tb_definition_content where definitionId = ? 
                    and statementTypeTransId = ?''', content):
                    postPopCheck = database.fetchone()
                    if postPopCheck == None:
                        database.execute('''insert into tb_definition_content values
                        (?, NULL, NULL, NULL, NULL, NULL, ?)''', content)
    except Exception as err:
        print("insertDefinition() Error: {0}".format(err))
        print("While parsing" + record[0] +'.\n')
        sys.exit()
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
    print("Workflow component v1.3: \n")
    print("Please be patient, this MAY take awhile...")
    print("While you're waiting, play a game:\nhttp://portal.wecreatestuff.com/portal.php")
    (inputFile, outputFile) = parse_cmd_args()
    lines = readInput( inputFile )
    seorigin( outputFile, lines )
    print("\nComplete! For your time, enjoy this picture of a cat:")
    print("http://catmacros.files.wordpress.com/2010/03/cat_portals.jpg\n")
    print("Enjoy your fresh new database! Be careful, it may be hot. ;)")
"""
The main function is run below.
"""
if __name__ == "__main__":
    main()
