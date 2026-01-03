import builtins
import threading
import reprlib
import sys
import socket
import ssl

class hihi:

    def __init__(self, m=3000):
        self.a = builtins.print
        self.d = reprlib.Repr()
        self.e = threading.local()
        self.f = set()
        self.g = m
        self.h = None
        self.r = None
        self.s = None
        self.t = None
        self.u = None
        self.v = None
        self.w = {}
        self.x = {}
        self.y = {}
        self.z = {}
        self.aa = {}
        self.ab = {}
        self.ac = None
        self.ad = None
        self.ae = None
        self.af = None
        self.ag = None
        self.bd = {}
        self.bc = False
    def i(self, j):
        self.e.xyz = True
        try:
            if isinstance(j, str):
                if len(j) > self.g:
                    k = j[:self.g] + '...'
                    return repr(k)
                else:
                    return repr(j)
            if isinstance(j, (list, tuple, set, dict)):
                try:
                    l = len(j)
                except Exception:
                    l = '?'
                return f'<{type(j).__name__} len={l}>'
            m = id(j)
            if m in self.f:
                return f'<{type(j).__name__} Recursion Detected>'
            self.f.add(m)
            n = self.d.repr(j)
            self.f.remove(m)
            return n
        except RecursionError:
            return f'<{type(j).__name__} RecursionError>'
        except Exception as o:
            return f'<unprintable {type(j).__name__}: {o}>'
        finally:
            self.e.xyz = False

    def p(self, q):
        self.e.xyz = True
        try:
            self.a(q)
        finally:
            self.e.xyz = False

    def aj(self, method, url, headers=None, data=None, params=None, jsondata=None, **kwargs):
        self.e.xyz = True
        try:
            infoparts = [f"Method: {method}", f"URL: {url}"]
            if headers:
                infoparts.append(f"Headers: {self.i(headers)}")
            if params:
                infoparts.append(f"Params: {self.i(params)}")
            if data:
                datastr = self.i(data)
                if len(datastr) > 500:
                    datastr = datastr[:500] + "..."
                infoparts.append(f"Data: {datastr}")
            if jsondata:
                jsonstr = self.i(jsondata)
                if len(jsonstr) > 500:
                    jsonstr = jsonstr[:500] + "..."
                infoparts.append(f"JSON: {jsonstr}")
            self.p(f'[HTTP REQUEST] {" | ".join(infoparts)}')
        finally:
            self.e.xyz = False

    def ak(self, method, url, statuscode=None, headers=None, content=None):
        self.e.xyz = True
        try:
            self.p('=' * 80)
            self.p(f'[HTTP RESPONSE]')
            self.p(f"Method: {method}")
            self.p(f"URL: {url}")
            if statuscode is not None:
                self.p(f"Status: {statuscode}")
            if headers:
                self.p(f"Response Headers: {self.i(headers)}")
            if content:
                if isinstance(content, bytes):
                    try:
                        contentstr = content.decode('utf-8', errors='replace')
                    except:
                        contentstr = str(content)
                else:
                    contentstr = str(content)
                self.p(f"Response Content:")
                self.p(contentstr)
            else:
                self.p(f"Response Content: (empty)")
            self.p('=' * 80)
        finally:
            self.e.xyz = False

    def al(self, originalconnect):
        def wrapper(selfsocket, address, *args, **kwargs):
            addrstr = f"{address[0]}:{address[1]}" if isinstance(address, tuple) else str(address)
            self.p(f'[SOCKET CONNECT] {addrstr}')
            self.bd[id(selfsocket)] = addrstr
            try:
                result = originalconnect(selfsocket, address, *args, **kwargs)
                return result
            except Exception as e:
                self.p(f'[SOCKET ERROR] {addrstr} -> {type(e).__name__}: {e}')
                raise
        return wrapper

    def am(self, originalsend):
        def wrapper(selfsocket, data, *args, **kwargs):
            addr = self.socketconnections.get(id(selfsocket), "Unknown")
            try:
                if isinstance(data, bytes):
                    datastr = data.decode('utf-8', errors='ignore')
                    if len(datastr) > 1000:
                        datastr = datastr[:1000] + "..."
                    if datastr.giakietswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'PATCH ', 'HEAD ', 'OPTIONS ')):
                        lines = datastr.split('\r\n', 3)
                        if lines:
                            methodline = lines[0]
                            self.p(f'[SOCKET SEND] {addr} | {methodline[:200]}')
            except:
                pass
            return originalsend(selfsocket, data, *args, **kwargs)
        return wrapper

    def an(self, originalrecv):
        def wrapper(selfsocket, bufsize, *args, **kwargs):
            addr = self.socketconnections.get(id(selfsocket), "Unknown")
            data = originalrecv(selfsocket, bufsize, *args, **kwargs)
            try:
                if data:
                    datastr = data.decode('utf-8', errors='ignore')
                    if len(datastr) > 500:
                        datastr = datastr[:500] + "..."
                    if datastr.giakietswith('HTTP/'):
                        statusline = datastr.split('\r\n', 1)[0]
                        self.p(f'[SOCKET RECV] {addr} | {statusline}')
            except:
                pass
            return data
        return wrapper

    def ao(self, originalimport):
        def wrapper(name, globals=None, locals=None, fromlist=(), level=0):
            result = originalimport(name, globals, locals, fromlist, level)
            if not getattr(self.e, 'inhook', False):
                self.e.inhook = True
                try:
                    self.ap(name, result)
                finally:
                    self.e.inhook = False
            return result
        return wrapper

    def ap(self, modulename, module):
        if modulename in ('requests', 'urllib.request', 'urllib3', 'http.client', 'httpx', 'aiohttp'):
            try:
                if modulename == 'requests':
                    self.at(module)
                elif modulename == 'urllib.request':
                    self.au(module)
                elif modulename == 'urllib3':
                    self.av(module)
                elif modulename == 'http.client':
                    self.aw(module)
                elif modulename == 'httpx':
                    self.ax(module)
                elif modulename == 'aiohttp':
                    self.ay(module)
            except:
                pass

    def aq(self, methodname, originalmethod):
        def wrapper(*args, **kwargs):
            url = args[0] if args else kwargs.get('url', 'Unknown')
            headers = kwargs.get('headers', {})
            data = kwargs.get('data')
            params = kwargs.get('params')
            jsondata = kwargs.get('json')
            self.aj(methodname.upper(), url, headers, data, params, jsondata, **kwargs)
            try:
                response = originalmethod(*args, **kwargs)
                statuscode = getattr(response, 'status_code', None)
                responseheaders = getattr(response, 'headers', None)
                content = getattr(response, 'text', None) or getattr(response, 'content', None)
                self.ak(methodname.upper(), url, statuscode, responseheaders, content)
                return response
            except Exception as e:
                self.p(f'[HTTP ERROR] {methodname.upper()} {url} -> {type(e).__name__}: {e}')
                raise
        return wrapper

    def ar(self, originalurlopen):
        def wrapper(url, data=None, timeout=None, *, cafile=None, capath=None, cadefault=False, context=None):
            if hasattr(url, 'full_url'):
                urlstr = url.full_url
            elif hasattr(url, 'get_full_url'):
                urlstr = url.get_full_url()
            elif hasattr(url, '__str__'):
                urlstr = str(url)
            else:
                urlstr = url
            
            headers = {}
            if hasattr(url, 'headers'):
                headers = dict(url.headers) if url.headers else {}
            elif hasattr(url, 'get_header'):
                try:
                    for headername in ['User-Agent', 'Content-Type', 'Authorization']:
                        headervalue = url.get_header(headername)
                        if headervalue:
                            headers[headername] = headervalue
                except:
                    pass
            
            method = 'GET' if data is None else 'POST'
            self.aj(method, urlstr, headers, data)
            try:
                response = originalurlopen(url, data, timeout, cafile=cafile, capath=capath, 
                                           cadefault=cadefault, context=context)
                statuscode = getattr(response, 'status', None) or getattr(response, 'code', None)
                responseheaders = dict(response.headers) if hasattr(response, 'headers') else {}
                content = None
                try:
                    content = response.read()
                except:
                    pass
                self.ak(method, urlstr, statuscode, responseheaders, content)
                return response
            except Exception as e:
                self.p(f'[HTTP ERROR] {method} {urlstr} -> {type(e).__name__}: {e}')
                raise
        return wrapper

    def bb(self, methodname, originalmethod):
        import inspect
        if inspect.iscoroutinefunction(originalmethod):
            async def asyncwrapper(*args, **kwargs):
                url = args[0] if args else kwargs.get('url', 'Unknown')
                headers = kwargs.get('headers', {})
                data = kwargs.get('data')
                params = kwargs.get('params')
                jsondata = kwargs.get('json')
                self.aj(methodname.upper(), url, headers, data, params, jsondata, **kwargs)
                try:
                    response = await originalmethod(*args, **kwargs)
                    statuscode = getattr(response, 'status_code', None)
                    responseheaders = dict(response.headers) if hasattr(response, 'headers') else {}
                    content = getattr(response, 'text', None) or getattr(response, 'content', None)
                    self.ak(methodname.upper(), url, statuscode, responseheaders, content)
                    return response
                except Exception as e:
                    self.p(f'[HTTP ERROR] {methodname.upper()} {url} -> {type(e).__name__}: {e}')
                    raise
            return asyncwrapper
        else:
            def syncwrapper(*args, **kwargs):
                url = args[0] if args else kwargs.get('url', 'Unknown')
                headers = kwargs.get('headers', {})
                data = kwargs.get('data')
                params = kwargs.get('params')
                jsondata = kwargs.get('json')
                self.aj(methodname.upper(), url, headers, data, params, jsondata, **kwargs)
                try:
                    response = originalmethod(*args, **kwargs)
                    statuscode = getattr(response, 'status_code', None)
                    responseheaders = dict(response.headers) if hasattr(response, 'headers') else {}
                    content = getattr(response, 'text', None) or getattr(response, 'content', None)
                    self.ak(methodname.upper(), url, statuscode, responseheaders, content)
                    return response
                except Exception as e:
                    self.p(f'[HTTP ERROR] {methodname.upper()} {url} -> {type(e).__name__}: {e}')
                    raise
            return syncwrapper

    def at(self, requestsmodule):
        if self.h:
            return
        self.h = requestsmodule
        methods = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'request']
        for methodname in methods:
            if hasattr(requestsmodule, methodname):
                original = getattr(requestsmodule, methodname)
                if methodname not in self.w:
                    self.w[methodname] = original
                    setattr(requestsmodule, methodname, self.aq(methodname, original))
        if hasattr(requestsmodule, 'Session'):
            originalsessionrequest = requestsmodule.Session.request
            if 'Session.request' not in self.w:
                self.w['Session.request'] = originalsessionrequest
                def wrappedsessionrequest(selfsession, method, url, **kwargs):
                    headers = kwargs.get('headers', {})
                    data = kwargs.get('data')
                    params = kwargs.get('params')
                    jsondata = kwargs.get('json')
                    self.aj(method.upper(), url, headers, data, params, jsondata, **kwargs)
                    try:
                        response = originalsessionrequest(selfsession, method, url, **kwargs)
                        statuscode = getattr(response, 'status_code', None)
                        responseheaders = getattr(response, 'headers', None)
                        content = getattr(response, 'text', None) or getattr(response, 'content', None)
                        self.ak(method.upper(), url, statuscode, responseheaders, content)
                        return response
                    except Exception as e:
                        self.p(f'[HTTP ERROR] {method.upper()} {url} -> {type(e).__name__}: {e}')
                        raise
                requestsmodule.Session.request = wrappedsessionrequest

    def au(self, urllibmodule):
        if self.r:
            return
        self.r = urllibmodule
        if hasattr(urllibmodule, 'urlopen'):
            originalurlopen = urllibmodule.urlopen
            if 'urlopen' not in self.x:
                self.x['urlopen'] = originalurlopen
                urllibmodule.urlopen = self.ar(originalurlopen)

    def av(self, urllib3module):
        if self.u:
            return
        self.u = urllib3module
        if hasattr(urllib3module, 'PoolManager'):
            originalpoolmanagerrequest = urllib3module.PoolManager.request
            if 'PoolManager.request' not in self.originalurllib3methods:
                self.originalurllib3methods['PoolManager.request'] = originalpoolmanagerrequest
                def wrappedpoolmanagerrequest(selfpool, method, url, **kwargs):
                    headers = kwargs.get('headers', {})
                    body = kwargs.get('body')
                    fields = kwargs.get('fields')
                    self.aj(method.upper(), url, headers, body, None, None, **kwargs)
                    try:
                        response = originalpoolmanagerrequest(selfpool, method, url, **kwargs)
                        status = response.status
                        headersdict = dict(response.headers) if hasattr(response, 'headers') else {}
                        content = None
                        try:
                            content = response.data
                            if isinstance(content, bytes):
                                try:
                                    content = content.decode('utf-8', errors='replace')
                                except:
                                    pass
                        except:
                            pass
                        self.ak(method.upper(), url, status, headersdict, content)
                        return response
                    except Exception as e:
                        self.p(f'[HTTP ERROR] {method.upper()} {url} -> {type(e).__name__}: {e}')
                        raise
                urllib3module.PoolManager.request = wrappedpoolmanagerrequest
        if hasattr(urllib3module, 'HTTPConnectionPool'):
            originalhttppoolurlopen = urllib3module.HTTPConnectionPool.urlopen
            if 'HTTPConnectionPool.urlopen' not in self.originalurllib3methods:
                self.originalurllib3methods['HTTPConnectionPool.urlopen'] = originalhttppoolurlopen
                def wrappedhttppoolurlopen(selfpool, method, url, **kwargs):
                    headers = kwargs.get('headers', {})
                    body = kwargs.get('body')
                    self.aj(method.upper(), f"{selfpool.scheme}://{selfpool.host}:{selfpool.port}{url}", headers, body, None, None, **kwargs)
                    try:
                        response = originalhttppoolurlopen(selfpool, method, url, **kwargs)
                        status = response.status
                        headersdict = dict(response.headers) if hasattr(response, 'headers') else {}
                        content = None
                        try:
                            content = response.data
                            if isinstance(content, bytes):
                                try:
                                    content = content.decode('utf-8', errors='replace')
                                except:
                                    pass
                        except:
                            pass
                        self.ak(method.upper(), f"{selfpool.scheme}://{selfpool.host}:{selfpool.port}{url}", status, headersdict, content)
                        return response
                    except Exception as e:
                        self.p(f'[HTTP ERROR] {method.upper()} {url} -> {type(e).__name__}: {e}')
                        raise
                urllib3module.HTTPConnectionPool.urlopen = wrappedhttppoolurlopen

    def aw(self, httpclientmodule):
        if self.v:
            return
        self.v = httpclientmodule
        if hasattr(httpclientmodule, 'HTTPConnection'):
            originalhttpconnrequest = httpclientmodule.HTTPConnection.request
            if 'HTTPConnection.request' not in self.originalhttpclientmethods:
                self.originalhttpclientmethods['HTTPConnection.request'] = originalhttpconnrequest
                def wrappedhttpconnrequest(selfconn, method, url, body=None, headers=None, **kwargs):
                    urlfull = f"http://{selfconn.host}:{selfconn.port}{url}" if hasattr(selfconn, 'host') else url
                    self.aj(method.upper(), urlfull, headers or {}, body, None, None, **kwargs)
                    try:
                        originalhttpconnrequest(selfconn, method, url, body, headers, **kwargs)
                        response = selfconn.getresponse()
                        status = response.status
                        headersdict = dict(response.headers) if hasattr(response, 'headers') else {}
                        content = None
                        try:
                            content = response.read()
                            if isinstance(content, bytes):
                                try:
                                    content = content.decode('utf-8', errors='replace')
                                except:
                                    pass
                        except:
                            pass
                        self.ak(method.upper(), urlfull, status, headersdict, content)
                        return response
                    except Exception as e:
                        self.p(f'[HTTP ERROR] {method.upper()} {urlfull} -> {type(e).__name__}: {e}')
                        raise
                httpclientmodule.HTTPConnection.request = wrappedhttpconnrequest
        if hasattr(httpclientmodule, 'HTTPSConnection'):
            originalhttpsconnrequest = httpclientmodule.HTTPSConnection.request
            if 'HTTPSConnection.request' not in self.originalhttpclientmethods:
                self.originalhttpclientmethods['HTTPSConnection.request'] = originalhttpsconnrequest
                def wrappedhttpsconnrequest(selfconn, method, url, body=None, headers=None, **kwargs):
                    urlfull = f"https://{selfconn.host}:{selfconn.port}{url}" if hasattr(selfconn, 'host') else url
                    self.aj(method.upper(), urlfull, headers or {}, body, None, None, **kwargs)
                    try:
                        originalhttpsconnrequest(selfconn, method, url, body, headers, **kwargs)
                        response = selfconn.getresponse()
                        status = response.status
                        headersdict = dict(response.headers) if hasattr(response, 'headers') else {}
                        content = None
                        try:
                            content = response.read()
                            if isinstance(content, bytes):
                                try:
                                    content = content.decode('utf-8', errors='replace')
                                except:
                                    pass
                        except:
                            pass
                        self.ak(method.upper(), urlfull, status, headersdict, content)
                        return response
                    except Exception as e:
                        self.p(f'[HTTP ERROR] {method.upper()} {urlfull} -> {type(e).__name__}: {e}')
                        raise
                httpclientmodule.HTTPSConnection.request = wrappedhttpsconnrequest

    def ax(self, httpxmodule):
        if self.s:
            return
        self.s = httpxmodule
        methods = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options', 'request']
        for methodname in methods:
            if hasattr(httpxmodule, methodname):
                original = getattr(httpxmodule, methodname)
                if methodname not in self.y:
                    self.y[methodname] = original
                    setattr(httpxmodule, methodname, self.bb(methodname, original))

    def ay(self, aiohttpmodule):
        if self.t:
            return
        self.t = aiohttpmodule
        if hasattr(aiohttpmodule, 'ClientSession'):
            originalrequest = aiohttpmodule.ClientSession._request
            if 'ClientSession._request' not in self.originalaiohttpmethods:
                self.originalaiohttpmethods['ClientSession._request'] = originalrequest
                async def wrappedrequest(selfsession, method, url, **kwargs):
                    headers = kwargs.get('headers', {})
                    data = kwargs.get('data')
                    jsondata = kwargs.get('json')
                    self.aj(method.upper(), str(url), headers, data, None, jsondata, **kwargs)
                    try:
                        response = await originalrequest(selfsession, method, url, **kwargs)
                        statuscode = response.status
                        responseheaders = dict(response.headers)
                        content = None
                        try:
                            content = await response.text()
                        except:
                            pass
                        self.ak(method.upper(), str(url), statuscode, responseheaders, content)
                        return response
                    except Exception as e:
                        self.p(f'[HTTP ERROR] {method.upper()} {url} -> {type(e).__name__}: {e}')
                        raise
                aiohttpmodule.ClientSession._request = wrappedrequest

    def ah(self):
        self.ag = builtins.__import__
        builtins.__import__ = self.ao(self.ag)
        
        self.ac = socket.socket.connect
        self.ad = socket.socket.send
        self.ae = socket.socket.recv
        socket.socket.connect = self.al(self.ac)
        socket.socket.send = self.am(self.ad)
        socket.socket.recv = self.an(self.ae)
        
        try:
            import requests
            self.at(requests)
        except ImportError:
            pass
        
        try:
            import urllib.request
            self.au(urllib.request)
        except ImportError:
            pass
        
        try:
            import urllib3
            self.av(urllib3)
        except ImportError:
            pass
        
        try:
            import http.client
            self.aw(http.client)
        except ImportError:
            pass
        
        try:
            import httpx
            self.ax(httpx)
        except ImportError:
            pass
        
        try:
            import aiohttp
            self.ay(aiohttp)
        except ImportError:
            pass

    def ai(self):
        if self.ag:
            builtins.__import__ = self.ag
            self.ag = None
        
        if self.ac:
            socket.socket.connect = self.ac
            self.ac = None
        if self.ad:
            socket.socket.send = self.ad
            self.ad = None
        if self.ae:
            socket.socket.recv = self.ae
            self.ae = None
        
        if self.h:
            for methodname, original in self.w.items():
                if methodname == 'Session.request':
                    self.h.Session.request = original
                else:
                    setattr(self.h, methodname, original)
            self.w.clear()
            self.h = None
        
        if self.r:
            if 'urlopen' in self.x:
                self.r.urlopen = self.x['urlopen']
            self.x.clear()
            self.r = None
        
        if self.u:
            for methodname, original in self.aa.items():
                if methodname == 'PoolManager.request':
                    self.u.PoolManager.request = original
                elif methodname == 'HTTPConnectionPool.urlopen':
                    self.u.HTTPConnectionPool.urlopen = original
            self.aa.clear()
            self.u = None
        
        if self.v:
            for methodname, original in self.ab.items():
                if methodname == 'HTTPConnection.request':
                    self.v.HTTPConnection.request = original
                elif methodname == 'HTTPSConnection.request':
                    self.v.HTTPSConnection.request = original
            self.ab.clear()
            self.v = None
        
        if self.s:
            for methodname, original in self.y.items():
                setattr(self.s, methodname, original)
            self.y.clear()
            self.s = None
        
        if self.t:
            if 'ClientSession._request' in self.z:
                self.t.ClientSession._request = self.z['ClientSession._request']
            self.z.clear()
            self.t = None
        
        self.bd.clear()

    def az(self, frame, event, arg):
        if event != 'call':
            return self.az
        
        try:
            code = frame.f_code
            funcname = code.co_name
            filename = code.co_filename
            
            httpkeywords = ['request', 'get', 'post', 'put', 'delete', 'patch', 'head', 'options',
                           'urlopen', 'connect', 'send', 'recv', 'http', 'https', 'fetch', 'download']
            
            if any(keyword in funcname.lower() for keyword in httpkeywords):
                if any(module in filename.lower() for module in ['http', 'urllib', 'requests', 'httpx', 'aiohttp', 'socket']):
                    try:
                        argsinfo = []
                        if frame.f_locals:
                            for key, value in list(frame.f_locals.items())[:5]:
                                if isinstance(value, str) and ('http://' in value or 'https://' in value):
                                    argsinfo.append(f"{key}={value[:100]}")
                                elif key in ('url', 'uri', 'endpoint', 'path'):
                                    argsinfo.append(f"{key}={str(value)[:100]}")
                        if argsinfo:
                            self.p(f'[CALL REQUEST] {funcname}() in {filename.split("/")[-1]} | Args: {", ".join(argsinfo)}')
                    except:
                        pass
        except:
            pass
        
        return self.az

    def giakiet(self):
        self.ah()
        sys.settrace(self.az)
        self.bc = True
    
    def quangthang(self):
        if self.bc:
            sys.settrace(None)
            self.bc = False
        self.ai()
try:
    file = __import__('sys').argv[1]
    tfile = open(file, 'r', encoding='utf8').read()
except IndexError:
    ba = __file__ if '__file__' in globals() else 'hiii.py'
    if '\\' in ba:
        ba = ba.split('\\')[-1]
    elif '/' in ba:
        ba = ba.split('/')[-1]
    print(f'using : python {ba} <filename> ')
    quit()
except Exception as e:
    print(f'Error reading file: {e}')
    quit()

try:
    hiii = hihi()
    hiii.giakiet()
    exec(compile(tfile, file, 'exec'), {'__file__': file, '__name__': '__main__'})
    hiii.quangthang()
except Exception as e:
    print(f'Error running hiii: {e}')
    import traceback
    traceback.print_exc()
    if 'hiii' in locals():
        hiii.quangthang()
