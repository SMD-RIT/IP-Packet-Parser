#define _BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <endian.h>

typedef struct packet_s{
  unsigned int IHL:4;
  unsigned int version:4;
  unsigned int TOS:8;
  unsigned int total_length:16;
  unsigned int id:16;
  unsigned int flag:3;
  unsigned int frag_offset:13;
  unsigned int TTL:8;
  unsigned int protocol:8;
  unsigned int checksum:16;
  unsigned int sAddress1:8;
  unsigned int sAddress2:8;
  unsigned int sAddress3:8;
  unsigned int sAddress4:8;
  unsigned int dAddress1:8;
  unsigned int dAddress2:8;
  unsigned int dAddress3:8;
  unsigned int dAddress4:8;
}Packet;

char* getTag(unsigned int num){
  char *tag;
  
  switch(num){
  case 1:
    tag = "ICMP";
    break;
  case 2:
    tag = "IGMP";
    break;
  case 6:
    tag = "TCP";
    break;
  case 9:
    tag = "IGRP";
    break;
  case 17:
    tag = "UDP";
    break;
  case 47:
    tag = "GRE";
    break;
  case 50:
    tag = "ESP";
    break;
  case 51:
    tag = "AH";
    break;
  case 57:
    tag = "SKIP";
    break;
  case 88:
    tag = "EIGRP";
    break;
  case 89:
    tag = "OSPF";
    break;
  case 115:
    tag = "L2TP";
    break;
  default:
    tag = "";
    break;
  }

  return tag;
}

int main(int argc, char **argv){
  //Read in filename.If no file name, print error message and quit.
  if(!(argc == 2)){
    fprintf(stderr, "Too many parameters were passed.\n");
    return EXIT_FAILURE;
  }
  char *filename = argv[1];
  
  //Open file.
  FILE* file = fopen(filename, "rb");
  
  //read in the number of packets to parse.
  int numPackets;
  int check = fread(&numPackets, sizeof(int), 1, file);
  if(check == 0){
    fprintf(stderr, "File was empty.\n");
    return EXIT_FAILURE;
  }
  
  fprintf(stdout, "=== File %s contains %d Packets\n", filename, numPackets);
  
  //Loop through the packets and print the header, packet length, and the data in the first 20 bytes.
  //USE FREAD
  for(int i = 1; i <= numPackets; ++i){
    int length;
    char buffer[2048];
    
    fread(&length, sizeof(int), 1, file);
    fread(&buffer, sizeof(char), length, file);

    //Split up data.
    Packet *data = (Packet*)buffer;

    //Print out packet elements.
    fprintf(stdout, "==>Packet %d\n", i);
    fprintf(stdout, "Version:\t\t%#x (%d)\n", data->version, data->version);
    fprintf(stdout, "IHL (Header Length):\t\t%#x (%d)\n", data->IHL, data->IHL);
    fprintf(stdout, "Type of Service (TOS):\t\t%#x (%d)\n", data->TOS, data->TOS);
    fprintf(stdout, "Total Length:\t\t%#x (%d)\n", be16toh(data->total_length), be16toh(data->total_length));
    fprintf(stdout, "Identification:\t\t%#x (%d)\n", be16toh(data->id), be16toh(data->id));
    fprintf(stdout, "IP Flags:\t\t%#x (%d)\n", data->flag, data->flag);
    fprintf(stdout, "Fragment Offset:\t\t%#x (%d)\n", data->frag_offset, data->frag_offset);
    fprintf(stdout, "Time To Live (TTL):\t\t%#x (%d)\n", data->TTL, data->TTL);
    fprintf(stdout, "Protocol:\t\t%s %#x (%d)\n",getTag(data->protocol), data->protocol, data->protocol);
    fprintf(stdout, "Header Checksum:\t\t%#x (%d)\n", be16toh(data->checksum), be16toh(data->checksum));
    fprintf(stdout, "Source Address:\t\t%d.%d.%d.%d\n",data->sAddress1, data->sAddress2, data->sAddress3, data->sAddress4);
    fprintf(stdout, "Destination Address:\t\t%d.%d.%d.%d\n", data->dAddress1, data->dAddress2, data->dAddress3, data->dAddress4);
  }
  
  //Close file.
  fclose(file);
  
  return EXIT_SUCCESS;
}
