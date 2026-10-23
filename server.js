const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const { MONGODB_URI, JWT_SECRET, PORT = 3000 } = process.env;
if (!MONGODB_URI || !JWT_SECRET) { console.error('Set MONGODB_URI and JWT_SECRET'); process.exit(1); }

const User = mongoose.model('User', new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  phone: { type: String, required: true, unique: true, match: /^\d{10}$/ },
  role: { type: String, enum: ['customer', 'supplier'], required: true },
  biz: { type: String, default: '', trim: true },
  pw: { type: String, required: true }
}));
const Product = mongoose.model('Product', new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  price: { type: Number, required: true, min: 0.01 },
  unit: { type: String, default: 'unit', trim: true },
  sup: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  biz: String
}, { timestamps: true }));
const Order = mongoose.model('Order', new mongoose.Schema({
  product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
  pname: String, unit: String, price: Number,
  qty: { type: Number, min: 1, required: true }, total: Number,
  sup: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  biz: String,
  cust: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  custName: String, custPhone: String,
  receiverName: { type: String, required: true, trim: true },
  receiverPhone: { type: String, required: true, match: /^\d{10}$/ },
  address: { type: String, required: true, minlength: 5, trim: true },
  status: { type: String, enum: ['Pending', 'Accepted', 'Delivered'], default: 'Pending' }
}, { timestamps: true }));

const app = express();
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const wrap = fn => (req, res) => fn(req, res).catch(e => {
  if (e.code === 11000) return res.status(409).json({ error: 'This phone is already registered.' });
  if (e.name === 'ValidationError') return res.status(400).json({ error: Object.values(e.errors)[0].message.replace(/Path `(\w+)`/, '$1') });
  console.error(e); res.status(500).json({ error: 'Server error' });
});
const sign = u => jwt.sign({ id: u._id, role: u.role }, JWT_SECRET, { expiresIn: '7d' });
const pub = u => ({ id: u._id, name: u.name, phone: u.phone, role: u.role, biz: u.biz });
const auth = role => (req, res, next) => {
  try {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    req.user = jwt.verify(t, JWT_SECRET);
    if (role && req.user.role !== role) return res.status(403).json({ error: 'Not allowed' });
    next();
  } catch { res.status(401).json({ error: 'Please log in again' }); }
};

app.post('/api/register', wrap(async (req, res) => {
  const { name, phone, password, role, biz } = req.body;
  if (!name || !/^\d{10}$/.test(phone || '')) return res.status(400).json({ error: 'Enter name and a 10-digit phone number.' });
  if (!password || password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
  if (!['customer', 'supplier'].includes(role)) return res.status(400).json({ error: 'Choose Customer or Supplier.' });
  if (role === 'supplier' && !biz) return res.status(400).json({ error: 'Enter your business name.' });
  const u = await User.create({ name, phone, role, biz: role === 'supplier' ? biz : '', pw: await bcrypt.hash(password, 10) });
  res.json({ token: sign(u), user: pub(u) });
}));

app.post('/api/login', wrap(async (req, res) => {
  const u = await User.findOne({ phone: String(req.body.phone || '') });
  if (!u || !(await bcrypt.compare(req.body.password || '', u.pw))) return res.status(401).json({ error: 'Wrong phone number or password.' });
  res.json({ token: sign(u), user: pub(u) });
}));

app.get('/api/products', auth(), wrap(async (req, res) => {
  const q = req.user.role === 'supplier' ? { sup: req.user.id } : {};
  res.json(await Product.find(q).sort('-createdAt'));
}));
app.post('/api/products', auth('supplier'), wrap(async (req, res) => {
  const me = await User.findById(req.user.id);
  const p = await Product.create({ name: req.body.name, price: Number(req.body.price), unit: req.body.unit || 'unit', sup: me._id, biz: me.biz || me.name });
  res.json(p);
}));
app.delete('/api/products/:id', auth('supplier'), wrap(async (req, res) => {
  await Product.deleteOne({ _id: req.params.id, sup: req.user.id });
  res.json({ ok: true });
}));

app.post('/api/orders', auth('customer'), wrap(async (req, res) => {
  const { productId, qty, receiverName, receiverPhone, address } = req.body;
  const p = await Product.findById(productId);
  if (!p) return res.status(404).json({ error: 'Product not found' });
  const me = await User.findById(req.user.id);
  const q = parseInt(qty);
  if (!(q >= 1)) return res.status(400).json({ error: 'Enter a valid quantity.' });
  const o = await Order.create({
    product: p._id, pname: p.name, unit: p.unit, price: p.price, qty: q, total: q * p.price,
    sup: p.sup, biz: p.biz, cust: me._id, custName: me.name, custPhone: me.phone,
    receiverName, receiverPhone, address
  });
  res.json(o);
}));
app.get('/api/orders', auth(), wrap(async (req, res) => {
  const q = req.user.role === 'supplier' ? { sup: req.user.id } : { cust: req.user.id };
  res.json(await Order.find(q).sort('-createdAt'));
}));
app.patch('/api/orders/:id/status', auth('supplier'), wrap(async (req, res) => {
  if (!['Accepted', 'Delivered'].includes(req.body.status)) return res.status(400).json({ error: 'Bad status' });
  const o = await Order.findOneAndUpdate({ _id: req.params.id, sup: req.user.id }, { status: req.body.status }, { new: true });
  if (!o) return res.status(404).json({ error: 'Order not found' });
  res.json(o);
}));

mongoose.connect(MONGODB_URI).then(() => {
  app.listen(PORT, () => console.log('Running on port ' + PORT));
}).catch(e => { console.error('MongoDB connection failed:', e.message); process.exit(1); });
