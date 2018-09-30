#!/bin/bash

#Install script for streamsplit

echo "Installing..."
sudo mkdir /opt/streamsplit
sudo cp streamsplit/* /opt/streamsplit
sudo ln -s /opt/streamsplit/streamsplit /usr/bin/streamsplit
sudo chmod 755 /opt/streamsplit
sudo chmod 755 /opt/streamsplit/*
sudo chmod 755 /usr/bin/streamsplit

echo "Complete."
