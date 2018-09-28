#!/bin/bash

#Install script for streamsplit

echo "Installling..."
sudo mkdir /opt/streamsplit
sudo cp streamsplit/* /opt/streamsplit
sudo ln -s /opt/streamsplit/streamsplit /usr/bin/streamsplit
echo "Complete."
