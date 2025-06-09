from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif, VarianceThreshold
from sklearn.decomposition import PCA
from sklearn.preprocessing import LabelEncoder
import numpy as np
import pandas as pd
import logging
from typing import Dict, List, Tuple
from decimal import Decimal
from sklearn.ensemble import RandomForestClassifier

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FeatureSelector:
    def __init__(self, n_features: int = 50):
        """
        Initialize the feature selector.
        
        Args:
            n_features: Number of features to select
        """
        self.n_features = n_features
        self.selected_features = None
        self.feature_importance = None
        self.selector = SelectKBest(f_classif, k=n_features)
    
    def select_features(self, features: pd.DataFrame, labels: np.ndarray = None) -> pd.DataFrame:
        """
        Select the most relevant features.
        
        Args:
            features: DataFrame containing the features
            labels: Optional array of labels for supervised feature selection
            
        Returns:
            DataFrame with selected features
        """
        try:
            # If labels are provided, use supervised feature selection
            if labels is not None:
                # Use Random Forest for feature importance
                rf = RandomForestClassifier(n_estimators=100, random_state=42)
                rf.fit(features, labels)
                
                # Get feature importance
                importance = pd.Series(rf.feature_importances_, index=features.columns)
                self.feature_importance = importance.sort_values(ascending=False)
                
                # Select top features
                self.selected_features = self.feature_importance.head(self.n_features).index.tolist()
                
            else:
                # Use unsupervised feature selection
                # Select features with highest variance
                variance = features.var()
                self.feature_importance = variance.sort_values(ascending=False)
                self.selected_features = self.feature_importance.head(self.n_features).index.tolist()
            
            # Return selected features
            return features[self.selected_features]
            
        except Exception as e:
            logger.error(f"Error selecting features: {str(e)}")
            # If there's an error, return all features
            self.selected_features = features.columns.tolist()
            self.feature_importance = pd.Series(1.0, index=features.columns)
            return features
    
    def get_selected_features(self) -> List[str]:
        """Get the list of selected feature names."""
        return self.selected_features if self.selected_features is not None else []
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance scores."""
        if self.feature_importance is not None:
            return self.feature_importance.to_dict()
        return {}
    
    def _convert_to_hashable(self, features: pd.DataFrame) -> pd.DataFrame:
        """Convert features to hashable types."""
        processed = features.copy()
        
        for column in processed.columns:
            # Convert Decimal/EDecimal to float
            if processed[column].dtype == 'object':
                try:
                    processed[column] = processed[column].apply(
                        lambda x: float(x) if isinstance(x, (Decimal, float)) else x
                    )
                except (TypeError, ValueError):
                    # If conversion fails, keep original values
                    pass
            
            # Convert sets to lists
            if processed[column].dtype == 'object':
                processed[column] = processed[column].apply(
                    lambda x: list(x) if isinstance(x, set) else x
                )
        
        return processed
    
    def _handle_categorical_features(self, features: pd.DataFrame) -> pd.DataFrame:
        """Handle categorical features by encoding them."""
        processed = features.copy()
        
        for column in processed.columns:
            if processed[column].dtype == 'object':
                try:
                    # Try to convert to numeric
                    pd.to_numeric(processed[column])
                except (ValueError, TypeError):
                    # If conversion fails, encode categorical values
                    if column not in self.label_encoders:
                        self.label_encoders[column] = LabelEncoder()
                        self.label_encoders[column].fit(processed[column].astype(str))
                    
                    processed[column] = self.label_encoders[column].transform(
                        processed[column].astype(str)
                    )
        
        return processed
    
    def _process_dictionary_features(self, features: pd.DataFrame) -> pd.DataFrame:
        """Process features that are stored as dictionaries."""
        processed = pd.DataFrame()
        
        for column in features.columns:
            if isinstance(features[column].iloc[0], dict):
                # Convert dictionary to separate columns
                dict_features = pd.DataFrame(features[column].tolist())
                processed = pd.concat([processed, dict_features], axis=1)
            else:
                processed[column] = features[column]
        
        return processed
    
    def _remove_constant_features(self, features: pd.DataFrame) -> pd.DataFrame:
        """Remove features with constant values."""
        constant_features = [col for col in features.columns 
                           if features[col].nunique() == 1]
        if constant_features:
            logger.info(f"Removing {len(constant_features)} constant features")
            features = features.drop(columns=constant_features)
        return features
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get the importance scores for selected features."""
        return self.feature_importance
    
    def get_selected_features(self) -> List[str]:
        """Get the names of selected features."""
        return self.selected_features 