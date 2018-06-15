#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cJSON.h"

#define cJSON_False 0
#define cJSON_True 1
#define cJSON_NULL 2
#define cJSON_Number 3
#define cJSON_String 4
#define cJSON_Array 5
#define cJSON_Object 6


char *cJSON_type[] = 
{
	"cJSON_False",
	"cJSON_True",
	"cJSON_NULL",
	"cJSON_Number",
	"cJSON_String",
	"cJSON_Array",
	"cJSON_Object",
	NULL

};


cJSON *cJSON_GetObjectItem_recu(cJSON *object,const char *string)
{
	cJSON *c=object->child; 

	while (c && cJSON_strcasecmp(c->string,string)) 
		c=c->next; 

	return c;

}


int main()
{

	cJSON *obj = NULL;
	cJSON *root = NULL;
	cJSON *array = NULL;

	char *out;

#if 1
	root = cJSON_CreateObject();
	cJSON_AddStringToObject(root, "lanIP", "123");
	
	cJSON_AddStringToObject(root, "lanMask", "456");



//	cJSON_AddItemToObject(root, "ddns", obj = cJSON_CreateObject());
    const char *arr[3] = {"tools", "computer", "soft"};
	cJSON_AddItemToObject(root, "ddns", obj = cJSON_CreateStringArray(arr, 3));
/*
	cJSON_AddStringToObject(obj, "ddnsEn", "true");
	cJSON_AddStringToObject(obj, "ddnsServiceName", "dyndns.org");


	cJSON_AddItemToObject(root, "dmz", obj = cJSON_CreateObject());
	
	cJSON_AddStringToObject(obj, "dmzEn", "true");
*/
	out = cJSON_Print(root);
	cJSON_Delete(root);
#else

	array = cJSON_CreateArray();
	obj = cJSON_CreateObject();
	cJSON_AddStringToObject(obj, "lan1\"\"\"$&*()'.", "br0");
	cJSON_AddStringToObject(obj, "wan1", "eth1");
	cJSON_AddItemToArray(array, obj);

	obj = cJSON_CreateObject();
	cJSON_AddItemToArray(array, obj);
	cJSON_AddStringToObject(obj, "lan2", "br1");
	cJSON_AddStringToObject(obj, "wan2", "vlan2");

	out = cJSON_Print(array);
	cJSON_Delete(array);
#endif
	printf("------------------------------\n");
	printf("%s", out);
	printf("\n------------------------------\n");


	cJSON *c;
	cJSON *tmp;
	c = cJSON_Parse(out);

	tmp = cJSON_GetObjectItem(c, "lanMask");
	printf("tmp->type=%s\n", cJSON_type[tmp->type]);
	printf("tmp->string=%s, tmp->valuestring=%s\n", tmp->string, tmp->valuestring);

	printf("c->type=%s\n", cJSON_type[c->type]);

	c = c->child;
	printf("c->type=%s\n", cJSON_type[c->type]);
	printf("c->string=%s, c->valuestring=%s\n", c->string, c->valuestring);

	c = c->next;
	printf("c->type=%s\n", cJSON_type[c->type]);
	printf("c->string=%s, c->valuestring=%s\n", c->string, c->valuestring);

	c = c->next;
	printf("c->type=%s\n", cJSON_type[c->type]);
	printf("c->string=%s, c->valuestring=%s\n", c->string, c->valuestring);	
	free(out);


	test1();
    
    cJSON *stat_root = NULL;
    elink_get_status_wifi(stat_root);
    
    
    
	return 0;
}

/*
“keymodelist”:
	[
		{“keymode”:	“dh”,	#密钥生成方式为DH方式},
	]

*/

void elink_get_status_wifi(cJSON *status_root)
{
	int ret = 0;
    cJSON *wifi_info = NULL;
    cJSON *ap_info = NULL;
    cJSON *radio_info = NULL;
    cJSON *wifi_tmp = NULL;
    cJSON *ap_tmp = NULL;

    int channel_info = 0;
	int channel_info_5g = 0;
	int power_level = 0;
	int power_level_5g = 0;
	char str_power_level[16] = {0};
    ap_status get_ap_status[4] = {0}; // 4 :qp count
    int ap_count = 0;
    int i = 0, j = 2;
	
    wifi_info = cJSON_CreateArray();
    radio_info = cJSON_CreateObject();

	//get wifi status
    for(i = 0; i < 2; i++) // i=0 :2.4G; i=1 : 5G;
	{     
		//memset(get_ap_status, 0x0, sizeof(get_ap_status)*4);
		wifi_tmp = cJSON_CreateObject();
		ap_info = cJSON_CreateArray();
		radio_info = cJSON_CreateObject();
        if(i == 0)
        {
            cJSON_AddStringToObject(radio_info,"mode","2.4G");
            cJSON_AddNumberToObject(radio_info,"channel", 6);
            cJSON_AddStringToObject(radio_info,"txpower", "100%");
        }
        else
        {
            cJSON_AddStringToObject(radio_info,"mode","5G");
            cJSON_AddNumberToObject(radio_info,"channel", 153);    
	    cJSON_AddStringToObject(radio_info,"txpower", "80%");
        }
        for(j = 0; j < 2; j++)// add ap
        {   
            //ap_info = cJSON_CreateArray();
            ap_count = i * 2 + j;
	 		ap_tmp = cJSON_CreateObject();
            if(0 == i)
            {
                //extra_get_2g_ap_status(j, &get_ap_status[ap_count]);
		       	printf("%s [%d][2.4G ap_count=%d][apidx=0][enable=yes][ssid=2.4G_test][key=12345678][auth=aes][encrypt=wpa2]\n",
			   	__FUNCTION__, __LINE__,ap_count);
                //if(!strcmp(get_ap_status[ap_count].enable_buf, "yes"))
                if(1)
                {   
                    cJSON_AddNumberToObject(ap_tmp, "apidx", get_ap_status[ap_count].apidx);    
                    cJSON_AddStringToObject(ap_tmp, "enable", get_ap_status[ap_count].enable_buf);
                    cJSON_AddStringToObject(ap_tmp, "ssid", get_ap_status[ap_count].ssid_buf);
                    cJSON_AddStringToObject(ap_tmp, "key", get_ap_status[ap_count].key_buf);
                    cJSON_AddStringToObject(ap_tmp, "auth", get_ap_status[ap_count].auth_buf);
                    cJSON_AddStringToObject(ap_tmp, "encrypt", get_ap_status[ap_count].encrypt_buf);
                }
                else
                {
                    cJSON_AddNumberToObject(ap_tmp, "apidx", get_ap_status[ap_count].apidx);
                    cJSON_AddStringToObject(ap_tmp, "enable", get_ap_status[ap_count].enable_buf);
                    cJSON_AddStringToObject(ap_tmp, "ssid", "");
                    cJSON_AddStringToObject(ap_tmp, "key", "");
                    cJSON_AddStringToObject(ap_tmp, "auth", "");
                    cJSON_AddStringToObject(ap_tmp, "encrypt", "");
                }       
	       //+redio
            }
            else
            {
                //extra_get_5g_ap_status(j, &get_ap_status[ap_count]);
		       	printf("%s [%d][5G ap_count=%d][apidx=1][enable=yes][ssid=5G_test][key=12345678][auth=aes][encrypt=wpa2]\n",
			   	__FUNCTION__, __LINE__,ap_count);
                if(1)
                {   
                    cJSON_AddNumberToObject(ap_tmp, "apidx", get_ap_status[ap_count].apidx);    
                    cJSON_AddStringToObject(ap_tmp, "enable", get_ap_status[ap_count].enable_buf);
                    cJSON_AddStringToObject(ap_tmp, "ssid", get_ap_status[ap_count].ssid_buf);
                    cJSON_AddStringToObject(ap_tmp, "key", get_ap_status[ap_count].key_buf);
                    cJSON_AddStringToObject(ap_tmp, "auth", get_ap_status[ap_count].auth_buf);
                    cJSON_AddStringToObject(ap_tmp, "encrypt", get_ap_status[ap_count].encrypt_buf);
                }
                else
                {
                    cJSON_AddNumberToObject(ap_tmp, "apidx", get_ap_status[ap_count].apidx);
                    cJSON_AddStringToObject(ap_tmp, "enable", get_ap_status[ap_count].enable_buf);
                    cJSON_AddStringToObject(ap_tmp, "ssid", "");
                    cJSON_AddStringToObject(ap_tmp, "key", "");
                    cJSON_AddStringToObject(ap_tmp, "auth", "");
                    cJSON_AddStringToObject(ap_tmp, "encrypt", "");
                }
            }
            cJSON_AddItemToArray(ap_info, ap_tmp);
        }
        cJSON_AddItemToObject(wifi_tmp, "radio", radio_info);
        cJSON_AddItemToObject(wifi_tmp,"ap",ap_info);
        cJSON_AddItemToArray(wifi_info,wifi_tmp);
    }
	
    cJSON_AddItemToObject(status_root, "wifi", wifi_info);    
}

int test1()
{
	char *out;
	cJSON *root;
    cJSON *array;

	cJSON *tmp;

	root = cJSON_CreateObject();
    array = cJSON_CreateArray();
    
    cJSON_AddItemToObject(root, "keymodelist", array);

    tmp = cJSON_CreateObject();
    cJSON_AddStringToObject(tmp, "keymode", "dh");

	cJSON_AddItemToArray(array, tmp);
    cJSON_AddItemToArray(array, cJSON_CreateString("wxy"));

	cJSON *root1;
	root1 = cJSON_CreateObject();
    cJSON_AddStringToObject(root1, "seq", "12345");
    cJSON_AddItemToArray(root1, root->child);
    
    out = cJSON_Print(root1);

    printf("out=======%s\n", out);

	return 0;
}
