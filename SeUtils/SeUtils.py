#!/usr/bin/env python
# Copyright 2013-2016 Jake Valletta (@jake_valletta)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""API for working with SEAndroid"""

from __future__ import absolute_import

import os.path
import re

from lxml import etree

from dtf.packages import launch_binary
from dtf.library import DbLibrary

import dtf.properties as prop
import dtf.logging as log

LIB_TAG = "SeDb"

FILE_TYPE_ORDINARY = 0
FILE_TYPE_BLOCK = 1
FILE_TYPE_CHAR = 2
FILE_TYPE_DIR = 3
FILE_TYPE_FIFO = 4
FILE_TYPE_SYM = 5
FILE_TYPE_SOCKET = 6

REGEX_META = ['.', '^', '$', '?', '*', '+', '|', '[', ']', '{']


def seapp_attrib(line, attrib, default):

    """Return seapp attrib"""

    compiled = re.compile("(%s=)([\._\-a-zA-Z0-9]*)" % attrib)

    matched = re.search(compiled, line)
    if matched is None:
        return default
    else:
        return matched.group(2)


def determine_type(type_str):

    """Determine the file type"""

    rtn = None

    if type_str == "--":
        rtn = FILE_TYPE_ORDINARY
    elif type_str == "-b":
        rtn = FILE_TYPE_BLOCK
    elif type_str == "-c":
        rtn = FILE_TYPE_CHAR
    elif type_str == "-d":
        rtn = FILE_TYPE_DIR
    elif type_str == "-p":
        rtn = FILE_TYPE_FIFO
    elif type_str == "-l":
        rtn = FILE_TYPE_SYM
    elif type_str == "-s":
        rtn = FILE_TYPE_SOCKET

    return rtn


def clean_context(context):

    """Strip info we dont need"""

    return context.replace("u:object_r:", '')[:-3]


# Exceptions
class SeDbException(Exception):

    """Generic exception"""

    def __init__(self, message):

        # Call the base class constructor with the parameters it needs
        Exception.__init__(self, message)


# ### Class SeDb ########################################
class SeDb(DbLibrary):

    """Class for manipulating SEAndroid information"""

    db_name = "se.db"

    def create_tables(self):

        """Create tables"""

        log.d(LIB_TAG, "Creating tables...")

        cur = self.get_cursor()

        # File contexts table
        sql = ('CREATE TABLE IF NOT EXISTS file_contexts('
               'id INTEGER PRIMARY KEY AUTOINCREMENT, '
               'pattern TEXT UNIQUE NOT NULL, '
               'type INTEGER DEFAULT 0, '
               'context TEXT NOT NULL)')

        cur.execute(sql)

        # Seapp contexts table
        sql = ('CREATE TABLE IF NOT EXISTS seapp_contexts('
               'id INTEGER PRIMARY KEY AUTOINCREMENT, '
               'user TEXT NOT NULL, '
               'seinfo TEXT, '
               'domain TEXT, '
               'name TEXT, '
               'type TEXT)')

        cur.execute(sql)

        # service contexts table
        sql = ('CREATE TABLE IF NOT EXISTS service_contexts('
               'id INTEGER PRIMARY KEY AUTOINCREMENT, '
               'name TEXT UNIQUE NOT NULL, '
               'context TEXT NOT NULL)')

        cur.execute(sql)

        # Mac permissions
        sql = ('CREATE TABLE IF NOT EXISTS mac_permissions('
               'id INTEGER PRIMARY KEY AUTOINCREMENT, '
               'signature TEXT, context TEXT NOT NULL)')

        cur.execute(sql)

        self.commit()
        return 0

    def drop_tables(self):

        """Drop tables"""

        cur = self.get_cursor()

        cur.execute('DROP TABLE IF EXISTS file_contexts')
        cur.execute('DROP TABLE IF EXISTS seapp_contexts')
        cur.execute('DROP TABLE IF EXISTS service_contexts')
        cur.execute('DROP TABLE IF EXISTS mac_permissions')

        return 0

    # Testers
    def has_service_contexts(self):

        """Determine if service_contexts exist for this device"""

        sql = ('SELECT COUNT(*) '
               'FROM service_contexts')

        cur = self.get_cursor()
        cur.execute(sql)

        (number_of_rows,) = cur.fetchone()

        if number_of_rows == 0:
            return False
        else:
            return True
    # End Testers

    # Parsers
    def parse_file_contexts(self, file_contexts):

        """Parse the file_contexts file"""

        file_contexts_f = open(file_contexts)

        contexts = list()

        for line in file_contexts_f.read().split("\n"):

            if line == "":
                continue
            if line[0] == "#":
                continue

            elements = line.split()

            # 3 elements means there is a type
            if len(elements) == 3:
                pattern, type_str, context = elements
                type_int = determine_type(type_str)
                if type_int is None:
                    log.e(LIB_TAG, "Unsupported type found: %s" % type_str)
                    continue

                contexts.append((pattern, type_int, context))

            elif len(elements) == 2:
                pattern, context = elements
                type_int = FILE_TYPE_ORDINARY

                contexts.append((pattern, type_int, context))

            else:
                log.w(LIB_TAG, "Found non-conforming line, skipping!")
                continue

        cursor = self.get_cursor()
        cursor.executemany('INSERT INTO file_contexts(pattern, type, context) '
                           'VALUES(?, ?, ?)', contexts)
        self.commit()
        return 0

    def parse_seapp_contexts(self, seapp_contexts):

        """Parse the seapp_contexts file"""

        seapp_contexts_f = open(seapp_contexts)

        contexts = list()

        for line in seapp_contexts_f.read().split("\n"):

            if line == "":
                continue

            user = seapp_attrib(line, "user", None)
            if user is None:
                log.d(LIB_TAG, "Skipping non-user entry")
                continue

            seinfo = seapp_attrib(line, "seinfo", None)
            name = seapp_attrib(line, "name", None)
            domain_t = seapp_attrib(line, "domain", None)
            type_t = seapp_attrib(line, "type", None)

            contexts.append((user, seinfo, name, domain_t, type_t))

        cursor = self.get_cursor()
        cursor.executemany('INSERT INTO seapp_contexts('
                           'user, seinfo, name, domain, type) '
                           'VALUES(?, ?, ?, ?, ?)', contexts)
        self.commit()
        return 0

    def parse_service_contexts(self, service_contexts):

        """Parse service contexts"""

        service_contexts_f = open(service_contexts)

        contexts = list()

        for line in service_contexts_f.read().split("\n"):

            if line == "":
                continue
            if line[0] == "#":
                continue

            elements = line.split()

            if len(elements) == 2:
                service_name, context_raw = elements

                if service_name == "*":
                    service_name = "DEFAULT"

                context_name = (context_raw.replace('u:object_r:', '')
                                .replace(':s0', ''))

                contexts.append((service_name, context_name))

            else:
                log.w(LIB_TAG, "Found non-conforming line, skipping!")
                continue

        cursor = self.get_cursor()
        cursor.executemany('INSERT INTO service_contexts(name, context) '
                           'VALUES(?, ?)', contexts)
        self.commit()
        return 0

    def parse_mac_permissions(self, mac_permissions_file):

        """parse the MAC permissions file"""

        mac_permissions_list = list()
        mac_permissions_f = open(mac_permissions_file)

        try:
            root = etree.XML(mac_permissions_f.read())
        except etree.XMLSyntaxError:
            log.e(LIB_TAG, "Unable to parse mac_permissions.xml!!")
            return -1

        # Signatures
        for signer in root.findall(".//signer"):

            signer_signature = signer.attrib['signature']
            seinfo_value = ""

            for child in signer:
                # TODO: support package stanzas
                if child.tag == "package":
                    log.w(LIB_TAG, "HEY! Figure this out!")
                elif child.tag == "seinfo":
                    seinfo_value = child.attrib['value']
                    mac_permissions_list.append((signer_signature,
                                                 seinfo_value))
                else:
                    log.e(LIB_TAG, "What is this? '%s'" % child.tag)

        # Default
        for default in root.findall(".//default"):

            # No signature associated with default.
            signer_signature = None

            # Default should only have one child, seinfo.
            seinfo = default[0]
            seinfo_value = seinfo.attrib['value']

            mac_permissions_list.append((signer_signature, seinfo_value))

        cursor = self.get_cursor()
        cursor.executemany('INSERT INTO mac_permissions(signature, context) '
                           'VALUES(?, ?)', mac_permissions_list)
        self.commit()
        return 0

# End Parsers

# Queries
    def get_mac_permissions(self):

        """Return mac permissions"""

        mac_perm_dict = dict()

        sql = ('SELECT context, signature '
               'FROM mac_permissions')

        cur = self.get_cursor()
        cur.execute(sql)

        for context, signature in cur.fetchall():
            mac_perm_dict[context] = signature

        return mac_perm_dict

    def get_seapp_rules(self):

        """Return list of seapp rules"""

        seapp_list = list()

        sql = ('SELECT user, seinfo, name, domain, type '
               'FROM seapp_contexts')

        cur = self.get_cursor()
        cur.execute(sql)

        for user, seinfo, name, domain_t, type_t in cur.fetchall():

            seapp_list.append((user, seinfo, name, domain_t, type_t))

        return seapp_list

    def get_service_contexts(self):

        """Return a list of service contexts"""

        service_dict = dict()

        sql = ('SELECT name, context '
               'FROM service_contexts')

        cur = self.get_cursor()
        cur.execute(sql)

        for name, context in cur.fetchall():

            service_dict[name] = context

        return service_dict
# End class SeDb


# File Parser Helper
class FileParser(object):

    """Class for performing file lookups"""

    file_file = None
    spec_list = None

    def __init__(self, file_file):

        """Object initialization for parser"""

        if not os.path.isfile(file_file):
            raise SeDbException("Contexts file '%s' not found!" %
                                file_file)

        self.file_file = file_file
        self.spec_list = list()

        file_f = open(file_file, 'r')

        for line in file_f.read().split("\n"):

            # Ignore comments and empty lines
            if line == '' or line[0] == '#':
                continue

            spec = dict()
            split_line = line.split()

            # 3 elements means there is a type
            if len(split_line) == 3:
                pattern, type_str, context = split_line
                type_int = determine_type(type_str)
                if type_int is None:
                    log.e(LIB_TAG, "Unsupported type found: %s" % type_str)
                    continue

            # 2 elements is no type
            elif len(split_line) == 2:
                pattern, context = split_line
                type_int = FILE_TYPE_ORDINARY

            else:
                log.w(LIB_TAG, "Found non-conforming line, skipping!")
                continue

            spec['pattern'] = pattern
            spec['type'] = type_int
            spec['context'] = clean_context(context)

            self.spec_list.append(spec)

        file_f.close()

    def __do_exact_match(self, file_path):

        """Try to do exact matching"""

        for spec in self.spec_list:

            # Ignore any regex
            if self.__has_meta_chars(spec):
                continue

            if spec['pattern'] == file_path:
                log.d(LIB_TAG, "Exact match found!")
                return spec

        return None

    def __do_regex_match(self, file_path):

        """Try to do regex matching"""

        matches_list = list()

        for spec in self.spec_list:

            # Only look at patterns
            if not self.__has_meta_chars(spec):
                continue

            log.d(LIB_TAG, "Trying pattern : %s" % spec['pattern'])

            try:
                pattern = re.compile(spec['pattern'])
            except re.error:
                log.e(LIB_TAG, "Error with regex: %s" % spec['pattern'])
                return None

            if re.match(pattern, file_path):
                log.d(LIB_TAG, "Appending match: %s" % spec['pattern'])
                matches_list.append(spec)

        return matches_list

    @classmethod
    def __find_best_match(cls, matches):

        """Find best match in list"""

        # We need to now pick the longest.
        longest = 0
        prev = 0
        i = 0

        while i < len(matches):

            cur = len(matches[i]['regex'])
            if prev < cur:
                longest = i

            prev = cur
            i += 1

        return matches[longest]

    @classmethod
    def __has_meta_chars(cls, spec):

        """Determine if regex is involved"""

        i = 0
        has_meta = False
        pattern = spec['pattern']

        while i < len(pattern):

            if pattern[i] in REGEX_META:
                has_meta = True
                break
            elif pattern[i] == '\\':
                i += 1
                continue
            else:
                i += 1

        return has_meta

    def get_file_context(self, file_path):

        """Determine the context for a give file"""

        # First, let's try exact match
        match = self.__do_exact_match(file_path)

        # If the match worked, we're done.
        if match is not None:
            match['exact'] = True
            return match

        # Now, lets do a regex match.
        matches = self.__do_regex_match(file_path)

        # Error or no matches?
        if matches is None or len(matches) == 0:
            return None

        # If there was only one match, return it.
        if len(matches) == 1:
            matches[0]['exact'] = False
            return matches[0]

        # Getting here means there are multiple matches.
        best_match = self.__find_best_match(matches)

        if best_match is None:
            return None
        else:
            best_match['exact'] = False
            return best_match


# Property Helper Class
class PropertyParser(object):

    """Class for performing property lookups"""

    property_file = None
    sorted_list = None

    def __init__(self, property_file):

        """Object initialization for parser"""

        if not os.path.isfile(property_file):
            raise SeDbException("Property file not found : %s!" %
                                property_file)

        self.property_file = property_file

        items = list()

        property_f = open(property_file, 'r')

        for line in property_f.read().split("\n"):

            # Ignore comments and empty lines
            if line == "" or line[0] == '#':
                continue

            item = dict()
            prop_prefix, context = line.split()

            item['prefix'] = prop_prefix
            item['context'] = clean_context(context)

            items.append(item)

        self.sorted_items = sorted(items, self.prop_cmp)
        property_f.close()

    @classmethod
    def prop_cmp(cls, rule_a, rule_b):

        """Sorter function"""

        # Retrofit: /platform/external/libselinux/src/label_android_property.c
        if rule_a['prefix'][0] == '*':
            return 1
        if rule_b['prefix'][0] == '*':
            return -1

        length_a = len(rule_a['prefix'])
        length_b = len(rule_b['prefix'])

        return (length_a < length_b) - (length_a > length_b)

    def match_context(self, prop_value):

        """Return context based on property"""

        for item in self.sorted_items:
            if item['prefix'] == prop_value[0:len(item['prefix'])]:
                return item['context']
            if item['prefix'][0] == '*':
                return item['context']

        return None

    def match_prefixes(self, context_list):

        """Return list of property prefixes available to a context"""

        prefix_list = list()

        for item in self.sorted_items:

            if item['context'] in context_list:
                prefix_list.append(item)

        return prefix_list
# End property helper


# Sesearch Helper
def sesearch(source, target, clazz, permission):

    """Perform a sesearch"""

    context_list = list()

    cmd_string = "-A "

    if source is not None:
        cmd_string += "-s %s " % source
    elif target is not None:
        cmd_string += "-t %s " % target
    else:
        return None

    if clazz is not None:
        cmd_string += "-c %s " % clazz
    if permission is not None:
        cmd_string += "-p %s " % permission

    cmd_string += "%s/seandroid/sepolicy" % prop.TOP

    out, err, rtn = launch_binary('sesearch', cmd_string)

    if rtn != 0:
        log.e(LIB_TAG, "Error running `sesearch` (%d)" % rtn)
        log.e_ml(LIB_TAG, err)
        return None

    for line in out:

        if line == '':
            continue

        # Third entry is the context
        entries = line.split()

        matched_context = entries[2].split(':')[0]
        context_list.append(matched_context)

    return context_list
