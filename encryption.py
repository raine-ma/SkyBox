from skein import threefish, skein1024
from sqlite3 import connect
from main import dbs
from json import loads
from requests import get
from flask import Flask, render_template, redirect, url_for, flash, request, session, g, send_file, abort, jsonify
from math import ceil
from os import getenv
def full():
  fileinfo = dbs(('SELECT Permission, Owner, Name, Size FROM Attachments WHERE ID = (?)', (id, )),False)
  key = session.get('fileviewkey')
  if key is None:
    return redirect(url_for("retrievefile",id=id))
  slt,passes = dbs(('SELECT Salt, Recurses FROM Attachments WHERE ID = (?)',(id,)),False)
  parts = loads(get(f"https://discord.com/api/v9/channels/{id}/messages/{id}",headers={"Authorization":getenv('Do')}).content.decode("utf-8"))
  with open('bruh.txt','w') as file:
    print('original hash:' +parts['content'], file=file)
    print(type(parts['content']), file=file)
  init = skein1024(key.encode(),nonce=slt.encode())
  for i in range(passes):
    init = skein1024(init.digest(),nonce=slt.encode())
  init = init.digest()
  #above is correct
  def one28(key,chunk):
    return threefish(key,key[-16:]).decrypt_block(chunk)
  at = one28(init,get(parts["attachments"][0]["url"]).content)
  with open('bruh.txt','w') as file:
    print('new hash '+skein1024(init=at).hexdigest(), file=file)
    print(type(skein1024(init=at).hexdigest()), file=file)
  if parts['content'] != skein1024(init=at).hexdigest():
    return 'Wrong password!'
  def dec_block(key,chunk,unpad=0):
    cipher = threefish(key,key[-16:])
    return b''.join([cipher.decrypt_block(chunk[i:i+128])[:-unpad] if i == len(chunk)-128 else cipher.decrypt_block(chunk[i:i+128]) for i in range(0,len(chunk),128)])
  #above is correct
  def enc_ret():
    yield at
    if fileinfo[3] > 10485760*99 + 128:
      first = True
      for i in range(ceil(fileinfo[3]/10485760)):
        if first:
          for i in range(100):
            parts = get(f"https://discord.com/api/v9/channels/{id}/messages?limit=100",headers={"Authorization":getenv('Do')}).json()[::-1]
            if i == 99:
              before = parts[i]["id"]
              yield dec_block(init,get(parts[i]["attachments"][0]["url"]).content)
              break
            else:
              yield dec_block(init,get(parts[i]["attachments"][0]["url"]).content)
          first = False
        else:
          parts = get(f"https://discord.com/api/v9/channels/{id}/messages?limit=100&?before={before}",headers={"Authorization":getenv('Do')}).json()[::-1]
          if parts == []:
            return
          if len(parts) < 100:
            for i in range(len(parts)):
              if i == len(parts) - 1 and parts[i]["content"] != '':    
                yield dec_block(init,get(parts[i]["attachments"][0]["url"]).content,unpad=int(parts[i]["content"].split(':')[1]))
              else:
                yield dec_block(init,get(parts[i]["attachments"][0]["url"]).content)
          else:
            for i in range(len(parts)):
              if i == 99 and parts[i]["content"] != '':
                before = parts[i]["id"]
                yield dec_block(init,get(parts[i]["attachments"][0]["url"]).content,unpad=int(parts[i]["content"].split(':')[1]))
                return
              elif i == 99 and parts[i]["content"] == '':
                before = parts[i]["id"]
                yield dec_block(init,get(parts[i]["attachments"][0]["url"]).content)
                break
              else:
                yield dec_block(init,get(i["attachments"][0]["url"]).content)
    else:
      f = get(f"https://discord.com/api/v9/channels/{id}/messages?limit=100",headers={"Authorization":getenv('Do')}).json()[::-1][1:]
      s = len(f)
      for i in range(s):
        if i == s-1:
          yield dec_block(init,get(f[i]["attachments"][0]["url"]).content,unpad=int(f[i]["content"].split(':')[1]))
          break
        else:
          yield dec_block(init,get(f[i]["attachments"][0]["url"]).content)
  return enc_ret(),{'Content-Disposition': f'attachment; filename={fileinfo[2]}','Content-Type': 'application/octet-stream',}


