const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const Lesson = require('./Lesson');  // Import Lesson model

// Define the User schema
const UserSchema = new Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true, select: false },
  avatar: { type: String },
  xp: { type: Number, default: 0 },  // XP towards the next level
  totalXp: { type: Number, default: 0 },  // Total accumulated XP
  level: { type: Number, default: 1 },  // Current user level
  xpNeededForNextLevel: { type: Number, default: 100 },
  streak: { type: Number, default: 0 },
  refreshToken: { type: String, select: false },  // New field for storing refresh token

  // Track lesson progress by section
  progress: [
    {
      sectionId: { type: String },
      lessonId: { type: String },
      completed: { type: Boolean, default: false },
      score: { type: Number, default: 0 },
      firstPerfectScore: { type: Boolean, default: false },
    },
  ],
  completedLessons: { type: [String], default: [] },  // Store completed lesson IDs

  resetPasswordToken: { type: String, select: false },
  resetPasswordExpire: { type: Date, select: false },
});

// Pre-save middleware to hash the password
UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

// Compare passwords during login
UserSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Generate password reset token
UserSchema.methods.generatePasswordResetToken = function () {
  const resetToken = crypto.randomBytes(32).toString('hex');
  this.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');
  this.resetPasswordExpire = Date.now() + 3600000;
  return resetToken;
};

// Calculate level based on XP
UserSchema.methods.calculateLevel = function () {
  let level = 1;
  let xpForNextLevel = 100;
  let remainingXP = this.totalXp;

  while (remainingXP >= xpForNextLevel) {
    remainingXP -= xpForNextLevel;
    level++;
    xpForNextLevel += 50;
  }

  this.level = level;
  this.xp = remainingXP;
  this.xpNeededForNextLevel = xpForNextLevel;
};

// Add XP and recalculate level
UserSchema.methods.addXP = function (xpEarned) {
  if (xpEarned <= 0) return;
  this.totalXp += xpEarned;
  this.calculateLevel();
};

// Clear refresh token on logout
UserSchema.methods.clearRefreshToken = async function () {
  this.refreshToken = '';
  await this.save();
};

// Mark a lesson as completed and unlock N+1 lessons
UserSchema.methods.completeLesson = async function (lessonId, score = 0) {
  if (!this.completedLessons.includes(lessonId)) {
    this.completedLessons.push(lessonId);
  }

  const lessonProgress = this.progress.find(
    (progress) => progress.lessonId.toString() === lessonId
  );

  if (lessonProgress) {
    lessonProgress.completed = true;
    lessonProgress.score = Math.max(lessonProgress.score, score);
  } else {
    const lesson = await Lesson.findById(lessonId);
    if (lesson) {
      this.progress.push({
        sectionId: lesson.sectionId,
        lessonId: lessonId,
        completed: true,
        score,
      });
    }
  }

  // Unlock the next N+1 lessons
  const completedCount = this.progress.filter((p) => p.completed).length;
  const lessonsToUnlock = completedCount + 1;

  const lessons = await Lesson.find({
    sectionId: lessonProgress.sectionId,
    order: { $lte: lessonsToUnlock },
  });

  lessons.forEach((lesson) => {
    const alreadyUnlocked = this.progress.some(
      (progress) => progress.lessonId.toString() === lesson._id.toString()
    );

    if (!alreadyUnlocked) {
      this.progress.push({
        sectionId: lesson.sectionId,
        lessonId: lesson._id.toString(),
        completed: false,
        score: 0,
      });
      console.log(`[UserModel] Unlocked lesson: ${lesson.title}`);
    }
  });
};

// Check if a lesson is completed
UserSchema.methods.isLessonCompleted = function (lessonId) {
  return this.completedLessons.includes(lessonId);
};

// Add an index on the `totalXp` field for leaderboard queries
UserSchema.index({ totalXp: -1 });

module.exports = mongoose.models.User || mongoose.model('User', UserSchema);
