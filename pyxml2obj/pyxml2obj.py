#!/usr/bin/python
# -*- coding: utf-8 -*-
#pylint: disable=C0103
#pylint: disable=R0201,R0901,R0902,R0903,R0904,R0911,R0912,R0914,R0915
#pylint: disable=E1101,E1103,E1120
#pylint: disable=W0201,W0231


""" Pyxml2obj """

import warnings
import re
from xml.sax import ContentHandler, parseString


def XMLin(content, options=None):
    """ Convert a XML string into object """

    if options is None:
        options = {}
    obj = xml2obj(options)
    obj.XMLin(content)
    return obj.tree


def XMLout(obj_tree, options=None):
    """ Convert an object into XML """

    if options is None:
        options = {}
    obj = xml2obj(options)
    xml_doc = obj.XMLout(obj_tree)
    return xml_doc


STRICT_MODE = 0
KNOWN_OPT_IN = \
    'keyattr keeproot forcecontent contentkey noattr \
               forcearray grouptags normalizespace valueattr'.split()
KNOWN_OPT_OUT = \
    'keyattr keeproot contentkey noattr singularize\
               rootname xmldecl noescape grouptags valueattr'.split()
DEFAULT_KEY_ATTR = 'name key id'.split()
DEFAULT_ROOT_NAME = 'root'
DEFAULT_CONTENT_KEY = 'content'
DEFAULT_XML_DECL = "<?xml version='1.0' standalone='yes'?>"


class xml2obj(ContentHandler):
    """ XML to object class """

    def __init__(self, options=None):

        if options is None:
            options = {}

        known_opt = {}
        for key in KNOWN_OPT_IN + KNOWN_OPT_OUT:
            known_opt[key] = None

        def_opt = {}
        for (key, val) in options.items():
            lkey = key.lower().replace('_', '')
            if not lkey in known_opt:
                raise KeyError('%s is not acceptable' % (lkey, ))
            def_opt[lkey] = val
        self.def_opt = def_opt

    def XMLin(self, content, options=None):
        """ Convert a XML string into object """

        if options is None:
            options = {}

        self.handle_options('in', options)
        self.build_tree(content)

    def build_tree(self, content):
        """ Create a content tree """

        parseString(content, self)

    def handle_options(self, dirn, options):
        """ Handler to current options """

        known_opt = {}
        if dirn == 'in':
            for key in KNOWN_OPT_IN:
                known_opt[key] = key
        else:
            for key in KNOWN_OPT_OUT:
                known_opt[key] = key

        row_opt = options
        self.opt = {}

        for (key, val) in row_opt:
            lkey = key.lower().replace('_', '')
            if key not in known_opt:
                raise KeyError('%s is not acceptable' % (key))
            self.opt[lkey] = val

        # marge in options passed to constructor

        for key in known_opt:
            if not key in self.opt:
                if key in self.def_opt:
                    self.opt[key] = self.def_opt[key]

        # set sensible defaults if not supplied

        if 'rootname' in self.opt:
            if not self.opt['rootname']:
                self.opt['rootname'] = ''
        else:
            self.opt['rootname'] = DEFAULT_ROOT_NAME

        if 'xmldecl' in self.opt and str(self.opt['xmldecl']) == '1':
            self.opt['xmldecl'] = DEFAULT_XML_DECL

        if 'contentkey' in self.opt:
            m = re.match('^-(.*)$', self.opt['contentkey'])
            if m:
                self.opt['contentkey'] = m.group(1)
                self.opt['collapseagain'] = 1
        else:
            self.opt['contentkey'] = DEFAULT_CONTENT_KEY

        if not 'normalizespace' in self.opt:
            self.opt['normalizespace'] = 0

        # special cleanup for forcearray

        if 'forcearray' in self.opt:
            if isinstance(self.opt['forcearray'], list):
                force_list = self.opt['forcearray']
                if len(force_list) > 0:
                    self.opt['forcearray'] = {}
                    for tag in force_list:
                        self.opt['forcearray'][tag] = 1
                else:
                    self.opt['forcearray'] = 0
        else:
            self.opt['forcearray'] = 0

        # special cleanup for keyattr

        if 'keyattr' in self.opt:
            if isinstance(self.opt['keyattr'], dict):

                # make a copy so we can mess with it

                self.keyattr = self.opt['keyattr']

                # Convert keyattr : {elem: '+attr'}
                # to keyattr : {elem: ['attr', '+']}

                for element in self.opt['keyattr']:
                    m = re.match(r'^(\+|-)?(.*)$',
                                 self.opt['keyattr'][element])
                    if m:
                        self.opt['keyattr'][element] = [m.group(2), m.group(1)]

                        if self.opt['forcearray'] == 1:
                            continue

                        if (isinstance(self.opt['forcearray'], dict) and
                                element in self.opt['forcearray']):
                            continue

                        if STRICT_MODE and dirn == 'in':
                            raise ValueError('<%s> set in KeyAttr but ' +
                                             'not in ForceArray'
                                             % (element))

                    else:
                        del self.opt['keyattr'][element]

            elif isinstance(self.opt['keyattr'], list):
                self.keyattr = self.opt['keyattr']
            else:
                self.opt['keyattr'] = [self.opt['keyattr']]
        else:
            if STRICT_MODE:
                raise ValueError("No value specified for " +
                                 "'KeyAttr' option in call to XML%s()"
                                 % (dirn, ))
            self.opt['keyattr'] = DEFAULT_KEY_ATTR

        # make sure there's nothing weired in grouptags

        if hasattr(self.opt, 'grouptags'):
            if not isinstance(self.opt['grouptags'], dict):
                raise ValueError("Illegal value for 'GroupTags' " +
                                 "option - expected a dictionary"
                                 )
            for (key, val) in self.opt['grouptags']:
                if key == val:
                    raise ValueError("Bad value in GroupTags: '%s' => '%s'"
                                     % (key, val))

        if 'valiables' in self.opt:
            self._var_values = self.opt['variables']
        elif 'varattr' in self.opt:
            self._var_values = {}

    def collapse(self, attr, obj_tree):
        """ Collapse current tree """

        # start with the hash of attributes

        if 'noattr' in self.opt:
            attr = {}

        elif ('normalizespace' in self.opt and
                self.opt['normalizespace'] == 2):

            for (key, val) in attr.items():
                attr[key] = self.normalize_space(val)

        for (key, val) in zip(obj_tree[::2], obj_tree[1::2]):
            if isinstance(val, list):
                val = self.collapse(val[0], val[1:])
                if not val and 'suppressempty' in self.opt:
                    continue
            elif key == '0':
                if re.match(r'^\s*$', val):  # skip all whitespace content
                    continue

                # do variable substitutions

                if hasattr(self, '_var_values'):
                    re.sub(
                        r'\$\{(\w+)\}',
                        lambda match: self.get_var(match.group(1)))

                # look for variable definitions

                if 'varattr' in self.opt:
                    var = self.opt['varattr']
                    if var in attr:
                        self.set_var(attr[var], val)

                # collapse text content in element with
                # no attributes to a string

                if not len(attr) and val == obj_tree[-1]:
                    return ({self.opt['contentkey']: val} if 'forcecontent'
                            in self.opt else val)
                key = self.opt['contentkey']

            # combine duplicate attributes

            if key in attr:
                if isinstance(attr[key], list):
                    attr[key].append(val)
                else:
                    attr[key] = [attr[key], val]
            elif val and isinstance(val, list):
                attr[key] = [val]
            else:

                if ('contentkey' in self.opt and
                    key != self.opt['contentkey'] and
                    (
                    self.opt['forcearray'] == 1
                        or isinstance(self.opt['forcearray'], dict)
                        and key in self.opt['forcearray'])):
                    attr[key] = [val]
                else:
                    attr[key] = val

        # turn array into hash if key fields present

        if 'keyattr' in self.opt:
            for (key, val) in attr.items():
                if val and isinstance(val, list):
                    attr[key] = self.array_to_hash(key, val)

        # disintermediate grouped tags

        if 'grouptags' in self.opt:
            for (key, val) in attr.items():
                if not (isinstance(val, dict) and len(val) == 1):
                    continue
                if not key in self.opt['grouptags']:
                    continue
                (child_key, child_val) = val.popitem()
                if self.opt['grouptags'][key] == child_key:
                    attr[key] = child_val

        # fold hashes containing a single anonymous array up
        # into just the array

        count = len(attr)
        if (count == 1 and 'anon' in attr and
                isinstance(attr['anon'], list)):
            return attr['anon']

        # do the right thing if hash is empty otherwise just return it

        if not len(attr) and 'suppressempty'in self.opt:
            if self.opt['suppressempty'] == '':
                return ''
            return None

        # roll up named elements with named nested 'value' attributes

        if 'valueattr' in self.opt:
            for (key, val) in attr.items():
                if not key in self.opt['valueattr']:
                    continue

                if not (isinstance(val, dict) and len(val) == 1):
                    continue

                k = val.keys()[0]
                if not k == self.opt['valueattr'][key]:
                    continue
                attr[key] = val[key]

        return attr

    def normalize_space(self, text):
        """ Normalize whitespaces """

        text = re.sub(r'\s\s+', ' ', text.strip())
        return text

    def singularize(self, word):
        """ Singularize an english word """

        if (not 'singularize' in self.opt):
            return 'anon'

        sing_rules = [
            lambda w: w[-3:] == 'ies' and w[:-3] + 'y',
            lambda w: w[-4:] == 'ives' and w[:-4] + 'ife',
            lambda w: w[-3:] == 'ves' and w[:-3] + 'f',
            lambda w: w[-2:] == 'es' and w[:-2],
            lambda w: w[-1:] == 's' and w[:-1],
            lambda w: w]

        word = word.strip()
        singleword = [f(word) for f in sing_rules if f(word)
                      is not False][0]
        return singleword

    # helper routine for collapse
    # attempt to 'fold' an array of hashes into an hash

    def array_to_hash(self, name, array):
        """ Convert an array to a dict """

        current_hash = {}

        # handle keyattr => {...}

        if isinstance(self.opt['keyattr'], dict):

            if not name in self.opt['keyattr']:
                return array

            (key, flag) = self.opt['keyattr'][name]

            for item in array:

                if isinstance(item, dict) and key in item:
                    val = item[key]

                    if isinstance(val, list) or isinstance(val, dict):

                        if STRICT_MODE:
                            raise ValueError(
                                "<%s> element has non-scalar'%s " % (name) +
                                "key attribute" % (key))

                        warnings.warn(
                            "Warn: <%s> element has non-scalar " % (name) +
                            "%s' key attribute" % (key))

                        return array
                    if self.opt['normalizespace'] == 1:
                        val = self.normalize_space(val)
                    current_hash[val] = item

                    if flag == '-':
                        current_hash[val]['-%s' % (key, )] = \
                            current_hash[val][key]

                    if flag != '+':
                        del current_hash[val][key]
                else:
                    if STRICT_MODE:
                        raise ValueError('<%s> element has no ' % (name) +
                                         '%s key attribute' % (key))

                    warnings.warn("Warn: <%s> element has " % (name) +
                                  "no '%s' key attribute" % (key))
                    return array
        else:

            # or assume keyattr => [...]

            for item in array:

                has_next = False
                if not isinstance(item, dict):
                    return array

                for key in self.opt['keyattr']:

                    if key in item:
                        val = item[key]
                        if isinstance(val, dict) or isinstance(val, list):
                            return array

                        if ('normalizespace' in self.opt and
                                self.opt['normalizespace'] == 1):
                            val = self.normalize_space(val)

                        current_hash[val] = item
                        del current_hash[val][key]
                        has_next = True
                        break

                if has_next:
                    continue
                return array

        # collapse any hashes which now only have a content key

        if 'collapseagain' in self.opt:
            current_hash = self.collapse_content(current_hash)

        return current_hash

    def collapse_content(self, current_hash):
        """ Collapse content """

        contentkey = self.opt['contentkey']

        # first go through the values, checking
        # that they are fit to collapse

        for val in current_hash.values():
            if not (isinstance(val, dict) and len(val) == 1
                    and contentkey in val):
                return current_hash

        # now collapse them

        for key in current_hash:
            current_hash[key] = current_hash[key][contentkey]

        return current_hash

    def XMLout(self, obj_tree, options=None):

        """ Convert an object into XML """

        if options is None:
            options = {}

        self.handle_options('out', options)

        # wrap to level list in a hash

        if isinstance(obj_tree, list):
            node_name = self.opt['rootname']
            obj_tree = {self.singularize(node_name): obj_tree}

        # extract rootname from top level if keeproot enabled

        if 'keeproot' in self.opt and self.opt['keeproot']:
            keys = obj_tree.keys()
            if len(obj_tree) == 1:
                obj_tree = obj_tree[keys[0]]
                self.opt['rootname'] = keys[0]
        elif self.opt['rootname'] == '':

            # ensure there are no top level attributes

            if isinstance(obj_tree, dict):
                treesave = obj_tree
                obj_tree = {}
                for key in treesave:
                    if (isinstance(treesave[key], dict) or
                            isinstance(treesave[key], list)):
                        obj_tree[key] = treesave[key]
                    else:
                        obj_tree[key] = [treesave[key]]

        # encode the tree

        self._ancestors = []
        xml_doc = self.value_to_xml(obj_tree, self.opt['rootname'], '')
        del self._ancestors
        if 'xmldecl' in self.opt and self.opt['xmldecl']:
            xml_doc = self.opt['xmldecl'] + '\n' + xml_doc

        return xml_doc

    def value_to_xml(self, obj_tree, name, indent):
        """ Convert a list, dict or scalar into xml """

        named = len(name) and 1 or 0
        nl = '\n'
        is_root = len(indent) == 0 and 1 or 0
        if 'noindent' in self.opt and self.opt['noindent']:
            indent = nl = ''

        # convert to xml

        if isinstance(obj_tree, list) or isinstance(obj_tree, dict):
            if len([elem for elem in self._ancestors if elem == obj_tree]):
                raise ValueError('circular data structures not supported')

            self._ancestors.append(obj_tree)

        else:

            if named:
                content = (obj_tree if 'noescape'
                           in self.opt else self.escape_value(obj_tree))
                line = \
                    '%s<%s>%s</%s>%s' \
                    % (indent, name, content, name, nl)
                return line
            else:
                return str(obj_tree) + nl

        # unfold hash to array if possible

        if (isinstance(obj_tree, dict) and len(obj_tree) and
                self.opt['keyattr'] and not is_root):
            obj_tree = self.hash_to_array(name, obj_tree)

        result = []

        # handle hash

        if isinstance(obj_tree, dict):

            # reintermediate grouped valued if applicable

            if 'grouptags' in self.opt and self.opt['grouptags']:
                obj_tree = obj_tree.copy()  # self.copy_hash(obj_tree)
                for (key, val) in obj_tree.items():
                    if key in self.opt['grouptags']:
                        obj_tree[key] = {self.opt['grouptags'][key]: val}

            nsdecls = ''

            #default_ns_url = ''

            nested = []
            text_content = None
            if named:
                result.extend([indent, '<', name, nsdecls])

            if len(obj_tree):

                #first_arg = 1

                for key in self.sorted_keys(name, obj_tree):
                    value = obj_tree[key]
                    if value is None:
                        if key[0] == '-':
                            continue
                        if key == self.opt['contentkey']:
                            text_content = ''
                        else:
                            value = ''

                    if isinstance(value, bool):
                        value = str(value).lower()

                    if (not isinstance(value, dict) and
                            not isinstance(value, list)):

                        if ('valueattr' in self.opt and
                                self.opt['valueattr']):

                            if (key in self.opt['valueattr'] and
                                    self.opt['valueattr'][key]):

                                value = {self.opt['valueattr'][key]: value}

                    if (isinstance(value, dict) or isinstance(value, list) or
                            'noattr' in self.opt):

                        nested.append(
                            self.value_to_xml(value, key, indent + '  '))
                    else:

                        if not ('noescape' in self.opt and
                                self.opt['noescape']):

                            value = self.escape_value(value)

                        if key == self.opt['contentkey']:
                            text_content = value
                        else:
                            result.extend([' ', key, '="', value, '"'])

                            #first_arg = 0

            else:
                text_content = ''

            if nested or text_content is not None:
                if named:
                    result.append('>')
                    if text_content is not None:
                        result.append(text_content)
                        if len(nested):
                            nested[0].lstrip()
                    else:
                        result.append(nl)
                    if len(nested):
                        result.extend(nested)
                        result.append(indent)
                    result.extend(['</', name, '>', nl])
                else:
                    result.extend(nested)
            else:
                result.extend([' />', nl])
        elif isinstance(obj_tree, list):

            # handle array

            for value in obj_tree:
                if (not isinstance(value, dict) and
                        not isinstance(value, list)):
                    result.extend(
                        [
                            indent, '<', name, '>',
                            (value if 'noescape' in self.opt
                             and self.opt['noescape']
                             else self.escape_value(value)),
                            '</', name, '>' + nl,
                        ])
                elif isinstance(value, dict):
                    result.append(self.value_to_xml(value, name,
                                  indent))
                else:
                    result.extend(
                        [
                            indent, '<', name, '>' + nl,
                            self.value_to_xml(value,
                                              self.singularize(name),
                                              indent + '  '),
                            indent, '</', name, '>' + nl,
                        ])
        else:
            raise ValueError("Can't encode a value of type: "
                             + obj_tree.__class__)

        if isinstance(obj_tree, dict) or isinstance(obj_tree, list):
            self._ancestors.pop()

        return ''.join(result)

    def sorted_keys(self, name, obj_tree):
        """ Sort the keys """

        _dict = obj_tree.copy()
        keyattr = self.opt['keyattr']
        key = []

        if isinstance(obj_tree, dict):
            if name in keyattr and keyattr[name][0] in _dict:
                key.append(keyattr[name][0])
                del _dict[keyattr[name][0]]
        elif isinstance(obj_tree, list):
            for item in keyattr:
                if item in _dict:
                    key.append(item)
                    del _dict[item]
                    break

        if len(_dict) > 0:
            tmp = _dict.keys()
            tmp.sort()
            key.extend(tmp)
        return key

    def escape_value(self, data):
        """ Escape tags """

        if data is None:
            return ''

        data = str(data)
        data = data.replace('&', '&amp;')
        data = data.replace('<', '&lt;')
        data = data.replace('>', '&gt;')
        data = data.replace('"', '&quot;')

        return data

    def hash_to_array(self, parent, _dict):
        """ Convert a dict to array """

        array = []
        for key in _dict:
            value = _dict[key]

            if not isinstance(value, dict):
                return _dict

            if isinstance(self.opt['keyattr'], dict):
                if not parent in self.opt['keyattr']:
                    return _dict

                array.append(
                    self.copy_hash(
                        value, [self.opt['keyattr'][parent][0], key]))
            else:
                array.append(
                    self.copy_hash(value, [self.opt['keyattr'][0], key]))
        return array

    def copy_hash(self, orig, extra):
        """ Copy hash method """

        result = orig.copy()
        result.update(dict(zip(extra[::2], extra[1::2])))
        return result

    # following methods overwrite ContentHandler

    def startDocument(self):
        self.lists = []
        self.curlist = self.tree = []

    def startElement(self, name, attrs):
        attributes = {}

        for attr in attrs.items():
            attributes[attr[0]] = attr[1]

        newlist = [attributes]
        self.curlist.extend([name, newlist])
        self.lists.append(self.curlist)
        self.curlist = newlist

    def characters(self, content):
        text = content
        pos = len(self.curlist) - 1

        if pos > 0 and self.curlist[pos - 1] == '0':
            self.curlist[pos] += text
        else:
            self.curlist.extend(['0', text])

    def endElement(self, name):
        self.curlist = self.lists.pop()

    def endDocument(self):
        del self.curlist
        del self.lists
        _tree = self.tree
        del self.tree

        if 'keeproot' in self.opt:
            _tree = self.collapse({}, _tree)
        else:
            _tree = self.collapse(_tree[1][0], (_tree[1])[1:])
        self.tree = _tree


if __name__ == '__main__':

#   opt = XMLin('''
#     <opt>
#       <item key="item1" attr1="value1" attr2="value2" />
#       <item key="item2" attr1="value3" attr2="value4" />
#     </opt>
#     ''', {'contentkey':'-content'})

    xml = \
        '''
    <opt>
      <car license="LW1804" make="GM"   id="2">
        <option key="1" pn="9926543-1167" desc="Steering Wheel"/>
      </car>
    </opt>
    '''
    opt = XMLin(xml, {'keyattr': {'car': 'license', 'option': 'pn'},
                'contentkey': '-content'})
    print opt

    hash1 = {'one': 1, 'two': 'II', 'three': '...'}
    xml = XMLout(hash1)

    tree = {'array': ['one', 'two', 'three']}
    expect = \
        '''
    <root>
      <array>one</array>
      <array>two</array>
      <array>three</array>
    </root>
    '''
    xml = XMLout(tree)

    tree = {'country': {'England': {'capital': 'London'},
            'France': {'capital': 'Paris'},
            'Turkey': {'capital': 'Istanbul'}}}
    expected = \
        r'''
^\s*<(\w+)\s*>\s*
(
   <country(\s*fullname="Turkey"  |\s*capital="Istanbul" ){2}\s*/>\s*
  |<country(\s*fullname="France"  |\s*capital="Paris"    ){2}\s*/>\s*
  |<country(\s*fullname="England" |\s*capital="London"   ){2}\s*/>\s*
){3}
</\1>\s*$
'''
    xml = XMLout(tree, {'keyattr': {'country': 'fullname'}})
    xml = XMLout(tree, {'keyattr': {'country': '+fullname'}})

    tree = {'one': 1, 'content': 'text'}
    xml = XMLout(tree)