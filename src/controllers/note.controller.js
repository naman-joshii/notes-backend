import Note from '../models/notes.model.js';


const getNotes = async (req, res) => {
  const notes = await Note.find({ user: req.user._id });
  res.json(notes);
};

const createNote = async (req, res) => {
  const { content } = req.body;
  if (!content) {
    return res.status(400).json({ message: 'Content cannot be empty' });
  }

  const note = new Note({
    content,
    user: req.user._id,
  });

  const createdNote = await note.save();
  res.status(201).json(createdNote);
};

const deleteNote = async (req, res) => {
  const note = await Note.findById(req.params.id);

  if (note) {
    if (note.user.toString() !== req.user._id.toString()) {
      return res.status(401).json({ message: 'Not authorized' });
    }
    await note.deleteOne();
    res.json({ message: 'Note removed' });
  } else {
    res.status(404).json({ message: 'Note not found' });
  }
};

export { getNotes, createNote, deleteNote };