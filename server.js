const express=require('express');
const http=require('http');
const {Server}=require('socket.io');
const bcrypt=require('bcryptjs');
const jwt=require('jsonwebtoken');
const fs=require('fs');
const path=require('path');
const crypto=require('crypto');
const app=express(),server=http.createServer(app),io=new Server(server);
const PORT=process.env.PORT||3000;
const SECRET=process.env.JWT_SECRET||'change-this-secret-before-deploying';
if(SECRET==='change-this-secret-before-deploying'&&process.env.NODE_ENV==='production')throw Error('Set JWT_SECRET in production');
const DB=path.join(__dirname,'nexus-data.json');
let data={users:[],messages:[],nextUser:1,nextMessage:1};
try{if(fs.existsSync(DB))data=JSON.parse(fs.readFileSync(DB,'utf8'))}catch(e){console.error('Cannot read nexus-data.json:',e.message);process.exit(1)}
function save(){const tmp=DB+'.tmp';fs.writeFileSync(tmp,JSON.stringify(data,null,2));fs.renameSync(tmp,DB)}
app.use(express.json({limit:'20kb'}));app.use(express.static(path.join(__dirname,'public')));
const tokenFor=u=>jwt.sign({id:u.id,username:u.username},SECRET,{expiresIn:'7d'});
function auth(req,res,next){try{req.user=jwt.verify((req.headers.authorization||'').replace(/^Bearer /,''),SECRET);next()}catch{return res.status(401).json({error:'Войдите в аккаунт'})}}
app.post('/api/register',(req,res)=>{let {username,password}=req.body||{};username=String(username||'').trim();password=String(password||'');if(!/^[\p{L}\p{N}_-]{3,24}$/u.test(username))return res.status(400).json({error:'Имя: 3–24 символа, буквы, цифры, _ или -'});if(password.length<8)return res.status(400).json({error:'Пароль должен быть не короче 8 символов'});if(data.users.some(u=>u.username.toLowerCase()===username.toLowerCase()))return res.status(409).json({error:'Это имя уже занято'});const u={id:data.nextUser++,username,password:bcrypt.hashSync(password,12)};data.users.push(u);save();res.json({token:tokenFor(u),user:{id:u.id,username:u.username}})});
app.post('/api/login',(req,res)=>{const {username,password}=req.body||{};const u=data.users.find(x=>x.username.toLowerCase()===String(username||'').trim().toLowerCase());if(!u||!bcrypt.compareSync(String(password||''),u.password))return res.status(401).json({error:'Неверное имя или пароль'});res.json({token:tokenFor(u),user:{id:u.id,username:u.username}})});
app.get('/api/me',auth,(req,res)=>res.json({user:{id:req.user.id,username:req.user.username}}));
app.get('/api/users',auth,(req,res)=>{const q=String(req.query.q||'').trim().slice(0,24).toLowerCase();res.json({users:q?data.users.filter(u=>u.id!==req.user.id&&u.username.toLowerCase().includes(q)).slice(0,20).map(u=>({id:u.id,username:u.username})):[]})});
app.get('/api/messages/:room',auth,(req,res)=>{const room=String(req.params.room).slice(0,100);res.json({messages:data.messages.filter(m=>m.room===room).slice(-100)})});
io.use((socket,next)=>{try{socket.user=jwt.verify(socket.handshake.auth?.token,SECRET);next()}catch{next(new Error('Не авторизован'))}});
io.on('connection',socket=>{socket.on('join',room=>{if(typeof room!=='string'||room.length>100)return;for(const r of socket.rooms)if(r!=='anonymous')socket.leave(r);socket.join(room)});socket.on('message',payload=>{if(!payload||typeof payload.room!=='string'||typeof payload.body!=='string')return;const room=payload.room.slice(0,100),body=payload.body.trim().slice(0,2000);if(!body)return;const msg={id:data.nextMessage++,room,username:socket.user.username,body,created_at:new Date().toISOString()};data.messages.push(msg);if(data.messages.length>10000)data.messages=data.messages.slice(-10000);save();io.to(room).emit('message',msg)})});
server.listen(PORT,()=>console.log(`NEXUS running at http://localhost:${PORT}`));
