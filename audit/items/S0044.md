---
name: Create quiz
description: Build practice quizzes and self-tests. Use when asked about "quiz", "practice test", "multiple choice", "self-assessment", or "test yourself".
metadata:
  author: curastem
  version: "1.0.0"
---

# Create Quiz

Guide students through creating practice quizzes and self-tests. Use Curastem's **mini app builder** for interactive multiple-choice or short-answer quizzes with instant feedback and scoring, or the **document editor** for written quiz formats they can print or copy.

## Curastem Tools to Use

### 1. Mini App Builder (create_app) — Primary Tool
Use to build interactive quizzes: show one question at a time, multiple-choice options or fill-in-the-blank, immediate feedback (correct/incorrect), and a final score. Output valid HTML with <style> and <script>. Follow Curastem guidelines: #141414 background, 48px top margin, Curastem.org label bottom-right, unique IDs on all interactive elements, mobile-responsive.

### 2. Document Editor (update_doc)
Use to draft quiz content before building: list questions with answer choices and correct answers. Create printable quiz formats or study guides. Format with <h2> for sections, <ol>/<li> for questions, <b> for correct answers (or separate answer key).

### 3. Whiteboard (update_whiteboard) — Optional
Use to plan quiz structure: flowchart of question flow, mind map of topics to cover, or diagram of question difficulty levels. Helps organize before building.

## When to Apply

- Student wants to create a practice quiz or self-test
- Student has exam material and wants to test their knowledge
- Student asks for multiple-choice or short-answer practice
- Student wants to gauge readiness before a test

## Workflow

1. **Gather** — Get their content: subject, questions, answer choices, correct answers
2. **Plan** — Optionally use whiteboard to structure topics and difficulty
3. **Build** — Use create_app for interactive quiz or update_doc for written format
4. **Refine** — Add more questions, fix answers, or adjust feedback based on results

## Key Guidance

- One question per screen in interactive quizzes; show feedback before next
- Include a final score or summary at the end
- Multiple-choice: 2–4 options; avoid trick questions for study quizzes
- For create_app: ensure all buttons and inputs have unique IDs
- Consider shuffling question order for varied practice
