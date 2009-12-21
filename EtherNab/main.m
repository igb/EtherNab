#include <stdio.h>
#include <pcap.h>


//
//  main.m
//  EtherNab
//
//  Created by Ian Brown on 12/19/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>

int main(int argc, char *argv[])
{
    char *dev = argv[1];
	
	printf("Device: %s\n", dev);
	return(0);
}
