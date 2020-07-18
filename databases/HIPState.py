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

HIP_STATE_UNASSOCIATED = 0x0;
HIP_STATE_I1_SENT      = 0x1;
HIP_STATE_I2_SENT      = 0x2;
HIP_STATE_R2_SENT      = 0x3;
HIP_STATE_ESTABLISHED  = 0x4;
HIP_STATE_CLOSING      = 0x5;
HIP_STATE_CLOSED       = 0x6;
HIP_STATE_E_FAILED     = 0x7;

class State():
	def __init__(self):
		self.state = HIP_STATE_UNASSOCIATED;
	def is_unassociated(self):
		return self.state == HIP_STATE_UNASSOCIATED;
	def unassociated(self):
		self.state = HIP_STATE_UNASSOCIATED;
	def is_i1_sent(self):
		return self.state == HIP_STATE_I1_SENT;
	def i1_sent(self):
		self.state = HIP_STATE_I1_SENT;
	def is_i2_sent(self):
		return self.state == HIP_STATE_I2_SENT;
	def i2_sent(self):
		self.state = HIP_STATE_I2_SENT;
	def is_r2_sent(self):
		return self.state == HIP_STATE_R2_SENT;
	def r2_sent(self):
		self.state = HIP_STATE_R2_SENT;
	def is_established(self):
		return self.state == HIP_STATE_ESTABLISHED;
	def established(self):
		self.state = HIP_STATE_ESTABLISHED;
	def is_closing(self):
		return self.state == HIP_STATE_CLOSING;
	def closing(self):
		self.state = HIP_STATE_CLOSING;
	def is_closed(self):
		return self.state == HIP_STATE_CLOSED;
	def closed(self):
		self.state = HIP_STATE_CLOSED;
	def is_failed(self):
		return self.state == HIP_STATE_E_FAILED;
	def failed(self):
		self.state = HIP_STATE_E_FAILED;

class StateMachine():
	def __init__(self):
		self.states = dict();
	def get(self, shit, rhit):

		if not self.states.get(shit+rhit, None):
			self.initialize(shit, rhit);
		return self.states.get(shit+rhit, None);
	def initialize(self, shit, rhit):

		self.states[shit+rhit] = State();

class Storage():
	def __init__(self):
		self.storage = dict();
	def get(self, shit, rhit):
		return self.storage.get(shit + rhit, None);
	def save(self, shit, rhit, value):
		self.storage[shit + rhit] = value;
	def remove(self, shit, rhit):
		del self.storage[shit + rhit]
