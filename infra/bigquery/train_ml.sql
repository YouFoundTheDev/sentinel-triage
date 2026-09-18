CREATE OR REPLACE MODEL {model}
OPTIONS(
  model_type = 'LOGISTIC_REG',
  input_label_cols = ['label'],
  auto_class_weights = TRUE,
  data_split_method = 'RANDOM',
  data_split_eval_fraction = 0.2
)
AS
SELECT * EXCEPT (url, domain, source)
FROM {features_table}
