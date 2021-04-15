import express from 'express';
import { txTest } from './aws-kms-sigining'

const app = express();
const port = 3000;
app.get('/', (req, res) => {
  res.send('The sedulous hyena ate the antelope!');
});


app.listen((port), () => {
    console.log("------listen--- ", port);
    txTest();
    return true
});

