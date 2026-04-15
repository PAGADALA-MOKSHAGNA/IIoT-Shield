### **Secondary ESP32 IIoT Node**



It Runs in the Station Mode, (i.e., it has its own IIoT Network).

The ESP32 runs a synchronous HTTP server. Each browser request is handled inside the main loop, where sensor values are dynamically embedded into HTML and sent back as a response.



The root endpoint serves the authenticated dashboard, while the /data endpoint acts as a backend API. The dashboard uses AJAX polling to fetch sensor data periodically without reloading the page.



### **ESP32 Promiscuous Node**



It does only the following operations:

1. Listens to raw Wi-Fi Frames
2. Extracts frame-level metadata
3. Counts Packages
4. Detects de-authentication frames



***"A Lightweight, behaviour-based wireless IDS Sensor"***



### **About Wi-Fi Channels**



**Wi-Fi channels are specific frequency ranges within a Wi-Fi band (such as 2.4 GHz or 5 GHz) used by routers and devices to transmit and receive data.**  Think of them as lanes on a highway—each channel allows wireless communication without interfering with others, helping multiple devices share the same network efficiently. 

* The 2.4 GHz band has 14 channels, but only channels 1, 6, and 11 are non-overlapping in most regions, making them the best choices to avoid interference. 
* The 5 GHz band offers more channels (up to 25 or more), with less congestion and higher speeds, ideal for bandwidth-intensive tasks like streaming or gaming. 
* The 6 GHz band (Wi-Fi 6E) introduces even more channels with minimal interference, supporting the fastest speeds and highest performance. 
