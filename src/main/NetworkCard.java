package main;

import jpcap.*;

public class NetworkCard {
	public static NetworkInterface[] getDevices() {
	    NetworkInterface[] devices = JpcapCaptor.getDeviceList();
		return devices;
	}
}
