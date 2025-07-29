import express from 'express';
import { getNotes, createNote, deleteNote } from '../controllers/note.controller.js';
import { protectedRoute } from '../middlewares/auth.middleware.js';


const router = express.Router();



router.route('/').get(protectedRoute, getNotes).post(protectedRoute, createNote);
router.route('/:id').delete(protectedRoute, deleteNote);

export default router;