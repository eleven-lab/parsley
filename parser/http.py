import traceback
import re
import logging
words = ['GET','POST','OK' ]

'''
if re.search(r'\bThis is correct\b', text):
    print('correct')
'''
def find_credentials ( fields ):
	#return fields[15]
	for word in fields:
		print ( word )
	for word in fields:
		#if ( "log" in word ): # not worked with this why?
		if ( re.search( "pwd", word ) ):
			#print("DIO")
			cred = word.split("&")
			creds = ( cred[0] + ":" + cred[1] )
			return creds

def parse_http ( src, dst, data ):
	try:
		logging.info ( "{} ----> {} SIZE: {}".format(src,dst,len(data)) )
		data = data.decode()
		fields = data.split("\r\n")
		#fields = fields[1:] #ignore the GET / HTTP/1.1
		#output = {}
		for word in words:
			#if ( word in fields[0] ): 
			if ( re.search( word, fields[0] ) and len( fields[0] ) < 2048 ): # u schif
				#logging.info ("{} ----> {}: {}".format( src, dst, fields[0] ) )
				logging.info ("{}".format( fields[0] ) )
				if ( 'POST' in fields[0] ): #post request
					creds = find_credentials ( fields )
					logging.info ( creds )

		'''
		for field in fields:
			print ( )
			#key,value = field.split(':')#split each line by http field name and value
			#output[key] = value
		'''
		#return output
		return
	except Exception: # VERY BAD
		#print ( "[!] It seems data can't be decoded!" )
		#print( traceback.format_exc() )
		return

