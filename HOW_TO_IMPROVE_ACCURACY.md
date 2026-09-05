# How to Improve Model Accuracy with User Feedback

## 🎯 Overview

The system now includes a **feedback loop** that learns from your decisions to improve detection accuracy over time.

## 📊 How It Works

### 1. **User Actions Trained as Labels**

When you interact with PDFs, your decisions are recorded:

- **Click "Block & Delete"** → File is labeled as **MALICIOUS**
- **Click "Anyway"** → File is labeled as **SAFE**
- **Dismiss** → No feedback (ignored)

### 2. **Feedback Collection**

- Each decision is sent to the backend
- Stored in `backend/feedback_data.jsonl`
- Includes: URL, actual label, predicted label, confidence, timestamp

### 3. **Automatic Retraining**

- When 50+ feedback samples are collected
- Run the retraining script
- Model learns from your corrections
- Accuracy improves over time

## 🚀 Step-by-Step Usage

### Step 1: Use the Extension Normally

1. Download PDFs as usual
2. When the popup appears:
   - If you know it's **malicious**: Click "Block & Delete"
   - If you know it's **safe**: Click "Anyway"
   - If unsure: Click "Dismiss" (no feedback)

### Step 2: Monitor Feedback Collection

Check the backend console for:
```
📊 Feedback received: malicious (predicted: safe)
✅ Feedback saved to feedback_data.jsonl
```

### Step 3: Retrain the Model

When you have enough feedback (50+ samples):

```bash
cd backend
python retrain_with_feedback.py
```

The script will:
1. Load feedback data
2. Download the PDFs from URLs
3. Extract features
4. Retrain the model
5. Save the updated model
6. Clear the feedback file

### Step 4: Restart the Backend

```bash
python main.py
```

The extension will now use the improved model!

## 📈 Expected Improvements

### Before Retraining:
- Model may misclassify some files
- False positives (safe files marked as malicious)
- False negatives (malicious files marked as safe)

### After Retraining:
- Model learns from your corrections
- Reduces false positives/negatives
- Better accuracy for your specific use cases
- Adapts to your PDF sources

## 🔍 Debugging

### Check Feedback Count

```bash
# Count feedback entries
wc -l backend/feedback_data.jsonl
```

### View Feedback Data

```bash
# View recent feedback
tail -10 backend/feedback_data.jsonl
```

### Manual Retraining

If you want to retrain before 50 samples:

```bash
# Edit retrain_with_feedback.py
# Change: if len(feedback_data) < 10:
# To: if len(feedback_data) < 5:

python retrain_with_feedback.py
```

## 💡 Best Practices

1. **Be Accurate**: Only block files you're sure are malicious
2. **Consistent Labels**: Same type of files should get same labels
3. **Diverse Data**: Train with various PDF sources
4. **Regular Retraining**: Retrain every 50-100 samples
5. **Backup Models**: Keep backups of good model versions

## 🎯 Tips for Better Accuracy

### For Malicious Files:
- Block files with JavaScript
- Block files from suspicious sources
- Block files with embedded executables
- Block files that fail to open properly

### For Safe Files:
- Allow files from trusted sources
- Allow files you've verified manually
- Allow standard document PDFs
- Allow files from official websites

## 📊 Monitoring Progress

Track improvement over time:

```python
# After each retraining, check:
# - Total feedback samples
# - Model accuracy on test set
# - False positive/negative rates
```

## 🔧 Troubleshooting

### Feedback Not Saving:
- Check backend is running
- Check console for errors
- Verify FEEDBACK_URL in background.js

### Retraining Fails:
- Check URLs are still accessible
- Check feature extraction is working
- Check model file permissions

### Model Not Improving:
- Need more diverse feedback
- Check feedback quality
- Verify labels are correct
- Consider original training data

## 🎉 Success Indicators

- ✅ Feedback count increasing
- ✅ Fewer false positives
- ✅ Fewer false negatives
- ✅ Higher confidence scores
- ✅ Better user experience

---

**The more you use it, the smarter it gets!** 🚀
