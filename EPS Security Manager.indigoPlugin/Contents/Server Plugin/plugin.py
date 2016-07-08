#! /usr/bin/env python
# -*- coding: utf-8 -*-
####################

import indigo

import os
import sys
import time
import datetime

################################################################################
class Plugin(indigo.PluginBase):
	#
	# Init
	#
	def __init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs):
		indigo.PluginBase.__init__(self, pluginId, pluginDisplayName, pluginVersion, pluginPrefs)
		self.debug = False
		
		self.devices = {}
		
	def __del__(self):
		indigo.PluginBase.__del__(self)
	
	
	#
	# One of our monitored devices has changed
	# 
	def deviceUpdated(self, origDev, newDev):
		# See if this device is in our list
		for devId, n in self.devices.iteritems():
			if devId == str(origDev.id):
				self.updateGroups (devId)
			
		return
		
	#
	# Rebuild our device list from scratch in case we removed one when we saved a device
	#
	def rebuildDeviceList (self):
		self.devices = {}
		
		devs = indigo.devices
		for dev in devs:
			if dev.pluginId == "com.eps.indigoplugin.security-manager":
				self.updateSecurityGroup (dev)
		
	#
	# Update groups that device belongs to
	#
	def updateGroups (self, devId):
		devs = indigo.devices
		for dev in devs:
			if dev.pluginId == "com.eps.indigoplugin.security-manager":
				if self.deviceInGroup (dev, devId):
					self.updateSecurityGroup (dev)
					
	#
	# Update security group state
	#
	def updateSecurityGroup (self, group):
		if self.deviceInsecure (group, "one"):
			group.updateStateOnServer("onOffState", False)
			return
		if self.deviceInsecure (group, "two"):
			group.updateStateOnServer("onOffState", False)
			return
		if self.deviceInsecure (group, "three"):
			group.updateStateOnServer("onOffState", False)
			return
		if self.deviceInsecure (group, "four"):
			group.updateStateOnServer("onOffState", False)
			return			
			
		group.updateStateOnServer("onOffState", True)
		
	#
	# Check if device is insecure
	#
	def deviceInsecure (self, group, n):
		if group.pluginProps:
			n = n # Just a placeholder so we can determine if we got here before we have pluginProps
		else:
			return True
		
		if group.pluginProps["device" + n] == "": return False
		
		dev = indigo.devices[int(group.pluginProps["device" + n])]
		
		if group.pluginProps["type" + n] == "onoff": return self.deviceInsecureOnOff (dev, group.pluginProps, n)
		if group.pluginProps["type" + n] == "sm": return self.deviceInsecureSM (dev, group.pluginProps, n)
		if group.pluginProps["type" + n] == "advanced": return self.deviceInsecureCustom (dev, group.pluginProps, n)
		if group.pluginProps["type" + n] == "io": return self.deviceInsecureIO (dev, group.pluginProps, n)
		
	#
	# On/off device is secure
	#
	def deviceInsecureOnOff (self, dev, props, n):
		if props["onoffsecuritystate" + n] == "off":
			if dev.states["onOffState"] == False: return True
		elif props["onoffsecuritystate" + n] == "on":
			if dev.states["onOffState"]: return True
				
		return False
		
	#
	# On/off device is secure
	#
	def deviceInsecureIO (self, dev, props, n):
		if props["iosecuritystate" + n] == "on":
			if dev.states[props["iosecurityinput" + n]]: return True
		elif props["iosecuritystate" + n] == "off":
			if dev.states[props["iosecurityinput" + n]] == False: return True	
		
		return False
		
	#
	# On/off device is secure
	#
	def deviceInsecureSM (self, dev, props, n):
		if dev.states["onOffState"] == False: return True
						
		return False
		
	# Custom state is insecure
	def deviceInsecureCustom (self, dev, props, n):
		if props["advstate" + n] in dev.states:
			try:
				if unicode(props["advvalue" + n]).lower() == "true": # Boolean true
					if dev.states[props["advstate" + n]]: return True
				if unicode(props["advvalue" + n]).lower() == "false": # Boolean false
					if dev.states[props["advstate" + n]] == False: return True
				if props["advvalue" + n][:1] == "\"": # String value
					checkvar = props["advvalue" + n]
					if dev.states[props["advstate" + n]] == checkvar.replace("\"",""): return True
				
				try:
					# Everything else should be numeric comparisons, but in we need to trap it so we can continue in case
					# none of the above conditions are true - causing this next statement to error out
					if dev.states[props["advstate" + n]] == int(props["advvalue" + n]): return True
				except:
					# Ignoring this exception
					x = 1
				
			except:
				indigo.server.log("Unable to compare the state of " + props["advstate" + n] + " to a value of " + props["advvalue" + n] + ".  Make sure you are comparing matching variable types (i.e., boolean to boolen, string to string, etc)")
				
		else:
			indigo.server.log (dev.name + " does not have a state of " + props["advstate" + n] + ", considering device insecure")
			return True
				
		return False
		
						
	# 
	# See if device belongs in group
	#
	def deviceInGroup (self, dev, devId):
		if dev.pluginProps["deviceone"] == devId: return True
		if dev.pluginProps["devicetwo"] == devId: return True
		if dev.pluginProps["devicethree"] == devId: return True
		if dev.pluginProps["devicefour"] == devId: return True
		
		return False
							
	#
	# Device configuration dialog closing
	#
	def validateDeviceConfigUi (self, valuesDict, typeId, devId):
		self.rebuildDeviceList ()
		self.addRemoveDevices (valuesDict)
		
		return True
		
	#
	# Add/remove devices from memory
	#
	def addRemoveDevices (self, values):
		self.addRemoveDevice (values, "one")
		self.addRemoveDevice (values, "two")
		self.addRemoveDevice (values, "three")
		self.addRemoveDevice (values, "four")
		
		
	#	
	# Add/remove single device from memory
	#
	def addRemoveDevice (self, values, n):
		if values["device" + n] != "":
			self.devices[values["device" + n]] = True
		else:
			self.devices.pop(values["device" + n], None)
		
	#
	# Show states button
	#
	def showStates (self, valuesDict, n):
		dev = indigo.devices[int(valuesDict["device" + n])]
		indigo.server.log(unicode(dev.states))
		
	#
	# Clear device button
	#
	def clearDevice (self, valuesDict, n):
		valuesDict["device" + n] = ""
		valuesDict["type" + n] = "onoff"
		
		return valuesDict
		
	#
	# Show states actions
	#
	def showStatesOne (self, valuesDict, typeId, devId): self.showStates (valuesDict, "one")
	def showStatesTwo (self, valuesDict, typeId, devId): self.showStates (valuesDict, "two")
	def showStatesThree (self, valuesDict, typeId, devId): self.showStates (valuesDict, "three")
	def showStatesFour (self, valuesDict, typeId, devId): self.showStates (valuesDict, "four")
		
	#
	# Clear device actions
	#
	def clearDeviceOne (self, valuesDict, typeId, devId): return self.clearDevice (valuesDict, "one")
	def clearDeviceTwo (self, valuesDict, typeId, devId): return self.clearDevice (valuesDict, "two")
	def clearDeviceThree (self, valuesDict, typeId, devId): return self.clearDevice (valuesDict, "three")
	def clearDeviceFour (self, valuesDict, typeId, devId): return self.clearDevice (valuesDict, "four")
		
	#
	# Plugin device start
	#	
	def deviceStartComm (self, dev):
		self.debugLog(u"device start comm called")
		self.addRemoveDevices (dev.pluginProps)
		self.updateSecurityGroup (dev)
		
	#
	# Plugin startup
	#
	def startup(self):
		self.debugLog(u"startup called")
		indigo.devices.subscribeToChanges()
		
	#	
	# Plugin shutdown
	#
	def shutdown(self):
		self.debugLog(u"shutdown called")

	#
	# Concurrent Threading
	#
	def runConcurrentThread(self):
		try:
			while True:
					#self.processTimer()
					self.sleep(1)
		except self.StopThread:
			pass	

	
