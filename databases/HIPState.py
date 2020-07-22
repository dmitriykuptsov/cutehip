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

# import libraries
# Timing
import time
# Utilities


HIP_STATE_UNASSOCIATED = 0x0;
HIP_STATE_I1_SENT      = 0x1;
HIP_STATE_I2_SENT      = 0x2;
HIP_STATE_R2_SENT      = 0x3;
HIP_STATE_ESTABLISHED  = 0x4;
HIP_STATE_CLOSING      = 0x5;
HIP_STATE_CLOSED       = 0x6;
HIP_STATE_E_FAILED     = 0x7;

DEFAULT_TIMEOUT_SECONDS = 5;

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
	def __str__(self):
		return str(self.state);
	def get_state(self):
		return self.state;

class StateMachine():
	def __init__(self):
		self.states = dict();
	def get(self, ihit, rhit):
		if not self.states.get(ihit+rhit, None):
			self.initialize(ihit, rhit);
		return self.states.get(ihit+rhit, None);
	def initialize(self, ihit, rhit):
		self.states[ihit+rhit] = State();

class Storage():
	def __init__(self):
		self.storage = dict();
	def get(self, ihit, rhit):
		return self.storage.get(ihit + rhit, None);
	def get_by_key(self, key):
		return self.storage.get(key, None);
	def save(self, ihit, rhit, value):
		self.storage[ihit + rhit] = value;
	def remove(self, ihit, rhit):
		del self.storage[ihit + rhit]
	def keys(self):
		return self.storage.keys();

class StateVariables():
	def __init__(self, state, ihit, rhit, src, dst):
		self.state = state;
		self.rhit  = rhit;
		self.ihit  = ihit;
		self.src   = src;
		self.dst   = dst;
		self.timer = time.time();
		self.update_timeout = time.time() + DEFAULT_TIMEOUT_SECONDS;
		self.i1_timeout = time.time() + DEFAULT_TIMEOUT_SECONDS;
		self.i1_retries = 0;
		self.i2_timeout = time.time() + DEFAULT_TIMEOUT_SECONDS;
		self.i2_retries = 0;
		self.i2_packet = None;
		self.update_seq = 0;
		self.is_responder = True;
		self.data_timeout = time.time() + DEFAULT_TIMEOUT_SECONDS;
		self.ec_complete_timeout = time.time() + DEFAULT_TIMEOUT_SECONDS;
		self.closing_timeout = time.time() + DEFAULT_TIMEOUT_SECONDS;
		self.closed_timeout = time.time() + DEFAULT_TIMEOUT_SECONDS;
		self.failed_timeout = time.time() + DEFAULT_TIMEOUT_SECONDS;

class KeyInfo():
	def __init__(self, info, salt, dh_group):
		self.info = info;
		self.salt = salt;
		self.dh_group = dh_group;