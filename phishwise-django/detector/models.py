from django.db import models
from django.db.models import Q
from django.conf import settings


class ScanHistory(models.Model):
	user = models.ForeignKey(
		settings.AUTH_USER_MODEL,
		on_delete=models.CASCADE,
		null=True,
		blank=True,
		related_name="scan_history",
	)
	url = models.TextField()
	source_type = models.CharField(max_length=20, default="direct_url")
	score = models.IntegerField()
	status = models.CharField(max_length=20)
	ai_risk_score = models.IntegerField()
	ssl_title = models.TextField()
	ssl_sub = models.TextField()
	domain_age = models.TextField()
	domain_sub = models.TextField()
	is_blacklisted = models.BooleanField(default=False)
	google_safe = models.BooleanField(default=True)
	location = models.TextField()
	has_redirection = models.BooleanField(default=False)
	timestamp = models.DateTimeField()

	def __str__(self):
		return f"{self.url} ({self.status})"

	@property
	def status_label(self):
		from .risk_levels import label_for_status

		return label_for_status(self.status)


class DomainStatistic(models.Model):
    """สถิติสะสมของการตรวจและรายงานสำหรับ hostname เดียวกัน."""
    domain = models.CharField(max_length=253, unique=True)
    scan_count = models.PositiveIntegerField(default=0)
    unique_scanner_count = models.PositiveIntegerField(default=0)
    report_count = models.PositiveIntegerField(default=0)
    approved_report_count = models.PositiveIntegerField(default=0)
    last_status = models.CharField(max_length=20, default="safe", blank=True)
    last_score = models.IntegerField(default=0, blank=True)
    scanned_by = models.ManyToManyField(settings.AUTH_USER_MODEL, blank=True, related_name="scanned_domains")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-updated_at",)

    def __str__(self):
        return f"{self.domain} ({self.last_status})"

    @property
    def status_label(self):
        from .risk_levels import label_for_status
        return label_for_status(self.last_status)



class SuspiciousSiteReport(models.Model):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    STATUS_CHOICES = ((PENDING, "รอตรวจสอบ"), (APPROVED, "อนุมัติแล้ว"), (REJECTED, "ปฏิเสธแล้ว"))
    REASON_CHOICES = (("phishing", "หลอกขโมยข้อมูล (Phishing)"), ("scam", "หลอกลวง/ฉ้อโกง"), ("malware", "อาจมีมัลแวร์หรือไฟล์อันตราย"), ("other", "อื่น ๆ"))
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="site_reports")
    domain = models.CharField(max_length=253, db_index=True)
    url = models.URLField(max_length=2048)
    reason = models.CharField(max_length=20, choices=REASON_CHOICES)
    details = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=PENDING, db_index=True)
    reviewed_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="reviewed_site_reports")
    reviewed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)
        constraints = [models.UniqueConstraint(fields=("user", "domain"), condition=Q(status__in=("pending", "approved")), name="one_open_or_approved_report_per_user_domain")]

    def __str__(self):
        return f"{self.domain} ({self.get_status_display()})"


class KnowledgeArticle(models.Model):
    CATEGORY_CHOICES = (
        ("Phishing", "Phishing"),
        ("Security", "Security"),
        ("Scams", "Scams"),
        ("Malware", "Malware"),
        ("Privacy", "Privacy"),
    )
    STATUS_DRAFT = "draft"
    STATUS_PUBLISHED = "published"
    STATUS_CHOICES = (
        (STATUS_DRAFT, "ฉบับร่าง"),
        (STATUS_PUBLISHED, "เผยแพร่แล้ว"),
    )

    title = models.CharField(max_length=255)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES)
    author = models.CharField(max_length=100, default="PhishWise Team")
    author_role = models.CharField(max_length=100, default="Cybersecurity Specialist")
    date = models.CharField(max_length=30, blank=True)
    read_time = models.CharField(max_length=30, blank=True)
    desc = models.TextField()
    image = models.CharField(max_length=500, blank=True, help_text="URL รูปภาพภายนอก หรือที่อยู่ไฟล์ที่อัปโหลด (/media/articles/...)")
    summary = models.TextField(blank=True)
    # sections: list ของ dict { title, text, image?, caption?, callout?, examples? }
    # key_takeaways: list ของ string
    content = models.JSONField(default=dict, blank=True, help_text='{"sections": [...], "key_takeaways": [...]}')
    content_markdown = models.TextField(blank=True, default="", help_text="Markdown ดิบตามที่แอดมินพิมพ์")
    content_html = models.TextField(blank=True, default="", help_text="HTML ที่ผ่านการ sanitize แล้ว")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_DRAFT)
    order = models.PositiveIntegerField(default=0, help_text="ลำดับการแสดงผล (น้อย = แสดงก่อน)")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("order", "-created_at")

    def __str__(self):
        return self.title

    @property
    def sections(self):
        return self.content.get("sections", [])

    @property
    def key_takeaways(self):
        return self.content.get("key_takeaways", [])