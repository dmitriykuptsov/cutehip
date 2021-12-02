#!/usr/bin/python3

# Copyright (C) 2019 strangebit

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

class Rule():
    def __init__(self, shit, dhit, allow = True):
        self.shit = shit;
        self.dhit = dhit;
        self.allow = allow;
    def get_src(self):
        return self.shit;
    def get_dst(self):
        return self.dhit;
    def is_allowed(self):
        return self.allow;

class BasicFirewall():
    def __init__(self):
        self.rules = [];

    def load_rules(self, file):
        fd = open(file, "r")
        rules = fd.readlines();
        for rule_desc in rules:
            parts = rule_desc.split(" ")
            rule = Rule(parts[0], parts[1], parts[2].strip() == "allow")
            self.rules.append(rule);
    
    def allow(self, shit, dhit):
        for rule in self.rules:
            if rule.get_src() == shit and rule.get_dst() == dhit:
                return rule.is_allowed();
        return False