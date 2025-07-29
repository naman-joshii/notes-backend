import mongoose from 'mongoose';

const noteSchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, required: true, ref: 'User' },
  content: { type: String, required: true },
}, { timestamps: true });

const Note = mongoose.model('Note', noteSchema);
export default Note;