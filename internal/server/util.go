package server

func metadataString(metadata map[string]interface{}, key string) string {
	if metadata == nil {
		return ""
	}
	if value, ok := metadata[key]; ok {
		if s, ok := value.(string); ok {
			return s
		}
	}
	return ""
}
