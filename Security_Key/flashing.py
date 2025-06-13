import time
import pandas as pd


server_negative_responses = {
    "10": "General Reject",
    "11": "Service not supported",
    "12": "Subfunction not supported",
    "13": "Incorrect message length or Invalid format",
    "14": "Response length exceeds the limit of the underlying transport protocol",
    "22": "Conditions not correct",
    "24": "Request Sequence Error",
    "31": "Request out of Range",
    "33": "Security Access Denied",
    "35": "Invalid Key",
    "36": "Exceed Number of Attempts",
    "71": "Transfer Data Suspended",
    "72": "General Programming Failure",
    "73": "Wrong Block Sequence Counter",
    "78": "Response pending",
    "7E": "Subfunction not supported in active diagnostic session",
    "7F": "Service not supported in active diagnostic session"
}


negative_responses = {
    '10': ['12','13','22','78','7E'],
    '19': ['11','12','13','31','78','7F'],
    '14': ['11','13','22','31','72','78','7F'],
    '11': ['12','13','22','33','78','7E','7F'],
    '22': ['13','14','22','31','33','7F'],
    '2E': ['13','22','31','33','72','7F'],
    '3E': ['12','13'],
    '27': ['12','13','22','24','35','36','7F'],
    '31': ['12','13','22','31','33','7F'],
    '85': ['12','13','22','31','7F'],
    '28': ['12','13','22','31','7F'],
    '34': ['13','22','31','33'],
    '23': ['13','22','31','33','7F'],
    '36': ['13','24','31','71','72','73','7F'],
    '37': ['13','24','31','72','7F'],
    '83': ['12','13','22','31'],
    '86': ['12','13','22','31'],
    '87': ['12','13','22','24','31'],
    '0C': ['12','13','22','33','7F'],
    '2F': ['13','22','31','33','7F']
}

##  ============================================== PRE PROGRAMMING ================================##

client_id='07B9'
server_id = '0729'

def check_negative_response(frame):
    requestId = frame[2]
    responseId = frame[3]
    if(frame[1]=='7F' and requestId in negative_responses and responseId in negative_responses[requestId]):
        print_negative_responce(responseId)
        return True # When it's  a negative response
    else:
        return False # When it's a positive response

def print_negative_responce(serviceId):
    print('\nGot negative response as '+serviceId+' which says:\n'+server_negative_responses[serviceId])

def checkTestPresent(data, id, index):
    # check test present with responce 
    if (id[index] == client_id and data[index][:3] == ['02', '3E', '00'] and 
        not(check_negative_response(data[index+1])) and 
        (id[index + 1] == server_id and data[index + 1][:3] == ['02', '7E', '00'])) :
        
        return checkAppliSoftwareInfo(data, id, index + 2)
    
    # check test present with responce suspended
    if (id[index] == client_id and data[index][:3] == ['02', '3E', '80']):
        return checkAppliSoftwareInfo(data, id, index + 1)
    
    return False,index


def check_info_sequence(data, id, index, request_id, request_data, response_id, response_data_prefix, consecutive_frames):
    # Check initial request
    if id[index] != request_id or data[index][:len(request_data)] != request_data:
        return False, index
    index += 1

    #check if it's a negative responce
    if check_negative_response(data[index]):
        return False,index

    # Check First Frame
    if id[index] != response_id or data[index][:len(response_data_prefix)] != response_data_prefix:
        return False, index
    index += 1

    # Check Flow Control
    if id[index] != request_id or data[index][0] != '30' or data[index][1] not in ['00', '03']:
        return False, index
    index += 1

    # Check Consecutive Frames
    for expected_data in consecutive_frames:
        if id[index] != response_id or data[index][0] != expected_data:
            return False, index
        index += 1
    return True, index


def checkAppliSoftwareInfo(data, id, index):
    print('Test Present  ✅')
    #check the Software info using check info sequence function
    success, index = check_info_sequence(
        data, id, index,
        request_id=client_id,
        request_data=['03', '22', 'F1', '81'],
        response_id=server_id,
        response_data_prefix=['10', '15', '62', 'F1', '81'],
        consecutive_frames=['21', '22', '23']
    )
    result_version_display=""
    if success:
        result_version_display+="Application Software Info (Version): \n"+" Minor: "+data[index-2][2]
        result_version_display+=" Major: "+data[index-2][3]+" Micro: "+data[index-2][4] +" Category: "+data[index-2][5]+'\n'
        print(result_version_display)

    return checkAppliHardwareInfo(data,id,index) if success else (False,index)


def checkAppliHardwareInfo(data, id, index):
    print('Application software info ✅')
    
    #check the Hardware info using check info sequence function
    success, index = check_info_sequence(
        data, id, index,
        request_id=client_id,
        request_data=['03', '22', 'F1', '93'],
        response_id=server_id,
        response_data_prefix=['10', '15', '62', 'F1', '93'],
        consecutive_frames=['21', '22', '23']
    )
    
    result_version_display=""
    if success :
        result_version_display+="Application Hardware Info (Version): \n"+"Minor: "+data[index-2][4]
        result_version_display+=" Major: "+data[index-2][5]+" Micro: "+data[index-2][6] +" BOM: "+data[index-2][7]+'\n'
        print(result_version_display)

    return checkbootLoaderSoftwareInfo(data,id,index) if success else (False,index)

def checkbootLoaderSoftwareInfo(data, id, index):
    print('Application Hardware info ✅')

    #check the Boot Loader Software info using check info sequence function
    success, index = check_info_sequence(
        data, id, index,
        request_id=client_id,
        request_data=['03', '22', 'F1', '85'],
        response_id=server_id,
        response_data_prefix=['10', '15', '62', 'F1', '85'],
        consecutive_frames=['21', '22', '23']
    )
    result_version_display=""
    if success:
        result_version_display+="BootLoader Software Info (Version): \n"+" Minor: "+data[index-2][2]
        result_version_display+=" Major: "+data[index-2][3]+" Micro: "+data[index-2][4] +" Category: "+data[index-2][5]+'\n'
        print(result_version_display)
    
    return checkDiagSessionControlExtended(data,id,index) if success else (False,index)

def check_DSC_Sequence(data,id,index,type):
    # check negative response 
        
    return ((id[index] == client_id and data[index][:3] == ['02', '10', type]) and 
            not(check_negative_response(data[index+1])) and 
            (id[index + 1] == server_id and data[index + 1][:3] == ['02', '50',type]))

def checkDiagSessionControlExtended(data, id, index):
    # before Starting Diagnostic Session Control there may be a Test Present or not
    print('Boot Loader Software ✅')
    # check test present with responce enabled
    if (id[index] == client_id and data[index][:3] == ['02', '3E', '00'] and
        not(check_negative_response(data[index+1])) and
        id[index + 1] == server_id and data[index + 1][:3] == ['02', '7E', '00']):
        print('Test Present ✅')
        return checkRoutineControlAndEDSC(data,id,index+4) if check_DSC_Sequence(data, id, index + 2,'03') else (False,index)
    
    # check test present with responce suspended
    if (id[index] == client_id and data[index][:3] == ['02', '3E', '80']):
        return checkRoutineControlAndEDSC(data,id,index+3) if check_DSC_Sequence(data, id, index + 1,'03') else (False,index)
    
    # check if log starts from application software info 
    return checkRoutineControlAndEDSC(data, id, index + 2) if check_DSC_Sequence(data, id, index, '03') else (False,index)


def checkRoutineControlAndEDSC(data,id,index):
    # check two steps in this function:
    #   1. Routine Control
    #   2. Extended DSC
    print('Extended DSC ✅')
    if (id[index]==client_id and data[index][1]=='31' and not(check_negative_response(data[index+1])) and 
    id[index+1]==server_id and data[index+1][1]=='71'):
        # use try block as string to int conversion is present
        try:
            length = int(data[index][0])
            for i in range(2, length + 1):
                if data[index][i] != data[index + 1][i]:
                    return False, index
        except IndexError:
            return False, index
        
        index+=2

        return checkControlDTCSetting(data, id, index + 2) if check_DSC_Sequence(data, id, index, '03') else (False,index)
    else:
        return False,index
        
def checkControlDTCSetting(data,id,index):
    print('Routine Control and Extended DSC ✅')
    if id[index]==client_id and data[index][1]=='85' and data[index][2] in ['81','82']:
        return checkCommunicationControl(data,id,index+1)
    elif(
        id[index] == client_id and data[index][1] == '85' and id[index + 1] == server_id and 
        not(check_negative_response(data[index+1])) and 
        data[index + 1][1] == 'C5' and data[index][2] == data[index + 1][2] and data[index][2] in ['01', '02']
    ):
        return checkCommunicationControl(data,id,index+2)
    else:
        return False,index

def checkCommunicationControl(data,id,index):
    print('Control DTC ✅')
    if id[index]==client_id and data[index][1]=='28' and data[index][2] in ['81','80'] and data[index][3] in ['01','02','03']:
        return finalPreProgrammingTestPresent(data,id,index+1)
    elif(
        id[index] == client_id and data[index][1] == '28' and id[index + 1] == server_id and
        not(check_negative_response(data[index+1])) and data[index + 1][1] == '68' and
        data[index][2] == data[index + 1][2] and data[index][2] in ['01', '00'] and
        data[index][3] == data[index + 1][3] and data[index][3] in ['01', '02','03']
    ):
        return finalPreProgrammingTestPresent(data,id,index+2)
    else:
        return False,index

def finalPreProgrammingTestPresent(data,id,index):
    print('communication control ✅')
    #check for test present with response
    if (id[index] == client_id and data[index][:3] == ['02', '3E', '00'] and
        id[index + 1] == server_id and not(check_negative_response(data[index+1]))
        and data[index + 1][:3] == ['02', '7E', '00']):
        return True,index+2
    
    # check test present with response suspended
    if (id[index] == client_id and data[index][:3] == ['02', '3E', '80']):
        return True,index+1
    
    return True,index

##  ============================================== PROGRAMMING ================================##

def checkDSCProgramming(data,id,index):
    #use DSC_sequence check function with type=01
    return checkSecurityAccess(data, id, index + 2) if check_DSC_Sequence(data, id, index, '02') else (False,index)

    
def checkSecurityAccess(data,id,index):
    #check security access folow as follows:
    # 1. Send seed request
    # 2. Get 8 byte  seed from server
    # 3. Send Key to the server
    # 4. If acctentication Successful we get positive response
    def verify_Security_Key(data,id,index):
    #helpher function for Security Access fucntion
        if (id[index]==client_id and data[index][:4]==['10', '0A', '27', '02'] and
            id[index+1]==server_id and data[index+1][:2] in [['30', '00'],['30','01']] and
            id[index+2]==client_id and data[index+2][:1]==['21'] and id[index+3]==server_id and
            not(check_negative_response(data[index+3])) and
            data[index+3][:3]==['02', '67', '02']):
            index+=4
            return True,index
        else:
            return False,index
        
    print('Program DSC ✅')
    if (id[index]==client_id and data[index][:3]==['02', '27', '01'] and id[index+1]==server_id and 
        not(check_negative_response(data[index+1]))
        and data[index+1][:4]==['10', '0A', '67', '01'] and
        id[index+2]==client_id and data[index+2][:2] in [['30', '00'],['30','01']] and
        id[index+3]==server_id and data[index+3][:1]==['21']):
        index+=4
        status,index = verify_Security_Key(data,id,index)

        return checkFingerPrint(data,id,index) if status else (False,index)
    else:
        return False,index

def checkFingerPrint(data,id,index):
    print('Security access ✅')
    if(id[index]==client_id and data[index][:5]==['05', '2E', 'F1', '84', '00'] and 
        data[index][5] in ['01','02','03','04','05']and id[index+1]==server_id and 
        not(check_negative_response(data[index+1])) and 
        data[index+1][:4]==['03', '6E', 'F1', '84']
       ):
        return checkEraseFlash(data,id,index+2)
    else:
        return False,index

def checkEraseFlash(data,id,index):
    print('Finger Print ✅')
    def check_response(data,id,index):
        return (id[index]==server_id and not(check_negative_response(data[index])) and
        data[index][:5]==['05', '71', '01' ,'FF', '00'] and data[index][5] in ['01','00'])
    
    if id[index]==client_id and data[index][:5]==['04', '31', '01' ,'FF', '00']:
        #check for test present if no test present is available then check responce
        index+=1
        if (id[index] == client_id and data[index][:3] == ['02', '3E', '00'] and
            not(check_negative_response(data[index][1])) and 
            id[index + 1] == server_id and data[index + 1][:3] == ['02', '7E', '00']):
            print('Test Present ✅')
            return checkRequestDownload(data,id,index+3) if check_response(data,id,index+2) else (False,index+2)
        
        # check test present with response suspended
        elif (id[index] == client_id and data[index][:3] == ['02', '3E', '80']):
            return checkRequestDownload(data,id,index+2) if check_response(data,id,index+1) else (False,index+2)
        else:
            return checkRequestDownload(data,id,index+1) if check_response(data,id,index) else (False,index+2)
    else:
        return False,index
    
def checkRequestDownload(data,id,index):
    print('Erase Flash ✅')
    if(id[index]==client_id and data[index][:5]==['10', '0B', '34', '00', '44'] and
        not(check_negative_response(data[index+1])) and 
        id[index+1]==server_id and data[index+1][:2]in[['30','00'],['30','01']] and 
        id[index+2]==client_id and data[index+2][0]=='21' and id[index+3]==server_id and
        not(check_negative_response(data[index+3])) and data[index+3][1]=='74'
        ):    
            if(data[index+3][2] not in ['00','10','20']): ## ==> correct code here should be '['10','20']'
                return False,index
            index+=3
            bytes = 1 if(data[index][2]=='10') else 2
            # as each block can send max of FFF so take 3 bytes of LSB (XU UU)
            length = data[index][3][1]+data[index][4] if(bytes==2) else data[index][3]
            try:
                num = int(length,16)
                num+=2
                hex_str = format(num, 'x')
            except IndexError:
                return False, index
                
            index+=1
            return checkTransferData(data,id,index,hex_str)
    else:
        return False,index
    
def checkTransferData(data,id,index,length):
    print('Request Download ✅')
    # Check Data Transfer and loop breaks, if transfer exit request came or due to error
    checkLength='1'+length
    i=1;prev=1;seq=33
    while(True):
        if(id[index]==client_id and (data[index][0]+data[index][1])<=checkLength and data[index][3]==format(i, '02X')):
            i = 0 if(i==255) else i+1
            index+=1;seq=33
        # check if frame is sent by server and if it is single frame check for negative response.
        elif(id[index]==server_id and data[index][0][0]=='0' and 
            check_negative_response(data[index])):
            break
        elif(id[index]==server_id and data[index][0]=='30'):
            index+=1
        elif(id[index]==client_id and data[index][0]==format(seq, '02X')):
            index+=1
            seq = 32 if(seq>=47) else seq+1
        elif(id[index]==server_id and data[index][:2]==['02', '76'] and data[index][2]==format(prev, '02X')):
            prev=i
            index+=1
        else:
            break
    # check for Transfer Exit
    print('Data Tranfer ✅')
    if(id[index]==client_id and data[index][:2]==['01', '37'] and
        id[index+1]==server_id and not(check_negative_response(data[index+1]))
        and data[index+1][:2]==['01', '77']):
            
        return checkTesterCheckSum(data,id,index+2)
    else:
        return False,index
        
def checkTesterCheckSum(data,id,index):
    print('Data Transfer Exit ✅')
    # Tester sends checksum to the server
    if(id[index]==client_id and data[index][1:4]==['2E', 'F1', 'A1'] and
        id[index+1]==server_id and not(check_negative_response(data[index+1]))
        and data[index+1][:4]==['03', '6E', 'F1', 'A1']):
        return checkMemory(data,id,index+2)
    else:
        return False,index

def checkMemory(data,id,index):
    print('Test Checksum ✅')

    if(id[index]==client_id and data[index][1:5]==['31', '01', '02', '02'] and
        id[index+1]==server_id and not(check_negative_response(data[index+1])) and
        data[index][2:5]==data[index+1][2:5] and data[index+1][1]=='71'):
        
        return checkECURest(data,id,index+2)
    else:
        return False,index
    
def checkECURest(data,id,index):
    print('Memory check ✅')
    success =  ((id[index] == client_id and data[index][:2] == ['02', '11']) and 
                data[index][2] in ['01','02','03']and (id[index + 1] == server_id and 
                not(check_negative_response(data[index+1])) and
                data[index + 1][:2] == ['02', '51']) and (data[index][2]==data[index+1][2] ))
    if success:
        print('ECU Reset ✅')
        return True,index+2
    else:
        return False,index

##  ============================================== POST PROGRAMMING ================================##

def checkDefaultDSC(data,id,index):
    #use DSC_sequence check function with type=01
    return checkPostSoftwareInfo(data, id, index + 2) if check_DSC_Sequence(data, id, index, '01') else (False, index)

def checkPostSoftwareInfo(data,id,index):
    print('Default DSC ✅')
    success, index = check_info_sequence(
        data, id, index,
        request_id=client_id,
        request_data=['03', '22', 'F1', '81'],
        response_id=server_id,
        response_data_prefix=['10', '15', '62', 'F1', '81'],
        consecutive_frames=['21', '22', '23']
    )
    if success:
        flag,index= checkPostHardwareInfo(data,id,index)
        return flag,index
    else:
        return False,index

def checkPostHardwareInfo(data,id,index):
    print('Software info ✅')
    success, index = check_info_sequence(
        data, id, index,
        request_id=client_id,
        request_data=['03', '22', 'F1', '93'],
        response_id=server_id,
        response_data_prefix=['10', '0F', '62', 'F1', '93'],
        consecutive_frames=['21', '22']
    )
    if success:
        flag,index= checkClearDTC(data,id,index)
        return flag,index
    else:
        return False,index
    
def checkClearDTC(data, id, index):
    print('Hardware info ✅')
    success =  (id[index] == client_id and data[index][:5] == ['04', '14', 'FF', 'FF', 'FF'] and
        id[index + 1] == server_id and not(check_negative_response(data[index+1]))
        and data[index + 1][:2] == ['01', '54'])
    if success:
        print('Clear DTC ✅') 
        return True, index+2
    else:
        return False, index

##  ==>Check Flashing

def checkPreprogramming(data,id,index):
    print('========= Pre Programming =========')
    flag,programmingIndex = checkTestPresent(data,id,index)
    if flag:
        print('\nPre Programming sequence is correct and programming start form ',programmingIndex+1,'\n')
        result = checkProgramming(data,id,programmingIndex)
        return result
    else:
        print('\nPre Programming sequence incorrect form ',programmingIndex+1,'\n')
        return False

def checkProgramming(data,id,index):
    print('========= Programming =========')
    flag,postProgrammingIndex = checkDSCProgramming(data,id,index)
    if flag:
        print('\nProgramming sequence is correct and Post Programming start form ',postProgrammingIndex+1,'\n')
        result = checkPostProgramming(data,id,postProgrammingIndex)
        return result
    else:
        print('\nProgramming sequence incorrect form ',postProgrammingIndex+1,'\n')

def checkPostProgramming(data,id,index):
    print('========= Post Programming =========')
    flag,index = checkDefaultDSC(data,id,index)
    if flag:
        print('\nPost Programming sequence is correct ','\n')
    else:
        print('\nPost Programming is not correct from ',index+1,'\n')
    
    return flag


def checkFlashingSequence(data,id,index):
    flag = checkPreprogramming(data,id,index)
    if flag:
        print('\nFlashing Sequence is verified')
    else:
        print('\nFlashing Sequence is not correct')



def analyze_flashing(df):
    logData = df['data']
    id = df['id']
    checkFlashingSequence(logData, id, 0)



# from dataGeneration import parse_trc_file   #  =======>>> For Testing flashing.py

# df = parse_trc_file('1stflashingLog.trc')

# analyze_flashing(df)



# == Used For debugging== #

# start =time.time()

# df = pd.read_csv('data.csv')
# logData = [ast.literal_eval(item) for item in df['data']]
# id = df['id']

# checkFlashingSequence(logData,id,0)

# end = time.time()

# print('\n inference time: ')
# print(end-start, " sec")