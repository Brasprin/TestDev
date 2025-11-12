import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(helmet());
app.use(express.json());
app.use(cors({ origin: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'], credentials: true }));
app.use(morgan('dev'));


const PORT = process.env.PORT || 0;
const NAME = process.env.SERVICE_NAME || 'service';
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/des_dev';

app.get('/health', (req, res) => res.json({ status: 'ok', service: NAME }));

export async function start() {
  await mongoose.connect(MONGO_URI);
  app.listen(PORT, () => console.log(`${NAME} listening on :${PORT}`));
}

if (process.env.NODE_ENV !== 'test') {
  start().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}

export default app;
